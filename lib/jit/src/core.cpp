#include "llvm/ExecutionEngine/JITSymbol.h"
#include "llvm/ExecutionEngine/Orc/CompileOnDemandLayer.h"
#include "llvm/ExecutionEngine/Orc/CompileUtils.h"
#include "llvm/ExecutionEngine/Orc/Core.h"
#include "llvm/ExecutionEngine/Orc/EPCIndirectionUtils.h"
#include "llvm/ExecutionEngine/Orc/ExecutionUtils.h"
#include "llvm/ExecutionEngine/Orc/IRCompileLayer.h"
#include "llvm/ExecutionEngine/Orc/IRTransformLayer.h"
#include "llvm/ExecutionEngine/Orc/JITTargetMachineBuilder.h"
#include "llvm/ExecutionEngine/Orc/RTDyldObjectLinkingLayer.h"
#include "llvm/ExecutionEngine/Orc/LazyReexports.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Scalar/GVN.h"

#include "llvm-c/Core.h"
#include "llvm-c/Orc.h"
#include "llvm-c/OrcEE.h"

#include <iostream>
#include <memory>

extern "C" {
  extern void* __trq_get_exception;
  extern void* __trq_personality_v0;
  extern void* __trq_throw;

  extern void* torque_lang_Integer;
  extern void* (*torque_lang_Integer_new(int64_t));
}

namespace llvm { 
  namespace orc {
    struct ast_layer_t;

    struct mat_unit_t : MaterializationUnit {
      typedef LLVMModuleRef (*emit_t)();

      std::string name;
      emit_t emit;
      ast_layer_t& layer;

      mat_unit_t(ast_layer_t& layer, const std::string& name, emit_t emit);

      StringRef getName() const override {
        return "TorqueMaterializationUnit";
      }

      void materialize(std::unique_ptr<MaterializationResponsibility> r) override;

      void discard(const JITDylib &jd, const SymbolStringPtr &sym) override {
        llvm_unreachable("Functions are not overridable");
      }
    };

    struct ast_layer_t {
      IRLayer &base_layer;
      const DataLayout &dl;

      ast_layer_t(IRLayer &base_layer, const DataLayout &dl)
        : base_layer(base_layer)
        , dl(dl)
      {}

      Error add(ResourceTrackerSP rt, const std::string& name, mat_unit_t::emit_t emit) {
        return rt->getJITDylib().define(
            std::make_unique<mat_unit_t>(
              *this,
              name, 
              std::move(emit)),
          rt);
      }

      void emit(
        std::unique_ptr<MaterializationResponsibility> mr,
        mat_unit_t::emit_t emit)
      {
        LLVMModuleRef module = emit();

        std::unique_ptr<Module> m(unwrap(module));

        ThreadSafeContext ctx(std::make_unique<LLVMContext>());
        ThreadSafeModule tsm(std::move(m), ctx);

        base_layer.emit(std::move(mr), std::move(tsm));
      }

      MaterializationUnit::Interface interface(const std::string& name, mat_unit_t::emit_t emit) {
        MangleAndInterner mangle(base_layer.getExecutionSession(), dl);
        SymbolFlagsMap symbols;
        symbols[mangle(name)] = JITSymbolFlags(JITSymbolFlags::Exported | JITSymbolFlags::Callable);

        return MaterializationUnit::Interface(std::move(symbols), nullptr);
      }
    };

    struct jit_t {
      std::unique_ptr<ExecutionSession> es;
      std::unique_ptr<EPCIndirectionUtils> epciu;

      DataLayout dl;
      MangleAndInterner mangle;

      RTDyldObjectLinkingLayer object_layer;
      IRCompileLayer           compile_layer;
      IRTransformLayer         optimize_layer;
      ast_layer_t              ast_layer;

      JITDylib &main_jd;

      jit_t(
        std::unique_ptr<ExecutionSession> es
      , std::unique_ptr<EPCIndirectionUtils> epciu
      , JITTargetMachineBuilder jtmb
      , DataLayout dl)
        : es(std::move(es))
        , epciu(std::move(epciu))
        , dl(std::move(dl))
        , mangle(*this->es, this->dl)
        , object_layer(*this->es, []() { return std::make_unique<SectionMemoryManager>(); })
        , compile_layer(*this->es, object_layer, std::make_unique<ConcurrentIRCompiler>(std::move(jtmb)))
        , optimize_layer(*this->es, compile_layer, optimize_module)
        , ast_layer(optimize_layer, this->dl)
        , main_jd(this->es->createBareJITDylib("<main>"))
      {
        main_jd.addGenerator(
          cantFail(DynamicLibrarySearchGenerator::GetForCurrentProcess(
            dl.getGlobalPrefix())));

        if(auto err = main_jd.define(
          absoluteSymbols({
            { mangle("malloc"), JITEvaluatedSymbol::fromPointer(&malloc)},
            { mangle("__trq_throw"), JITEvaluatedSymbol::fromPointer(__trq_throw)},
            { mangle("__trq_get_exception"), JITEvaluatedSymbol::fromPointer(__trq_get_exception)},
            { mangle("__trq_personality_v0"), JITEvaluatedSymbol::fromPointer(__trq_personality_v0)},
            { mangle("torque_lang_Integer"), JITEvaluatedSymbol::fromPointer(torque_lang_Integer)},
            { mangle("torque_lang_Integer_new"), JITEvaluatedSymbol::fromPointer(torque_lang_Integer_new)},
          }))) {
          throw std::runtime_error("Error while starting JIT. Can't define symbols");
        }
      }

      const DataLayout &get_data_layout() const { return dl; }

      JITDylib &get_main_jit_dylib() { return main_jd; }

      Error add(ThreadSafeModule tsm, ResourceTrackerSP rt = nullptr) {
        if (!rt)
          rt = main_jd.getDefaultResourceTracker();

        return optimize_layer.add(rt, std::move(tsm));
      }

      Error add(const std::string& name, mat_unit_t::emit_t emit, ResourceTrackerSP rt = nullptr) {
        if (!rt)
          rt = main_jd.getDefaultResourceTracker();

        return ast_layer.add(rt, name, std::move(emit));
      }

      Expected<JITEvaluatedSymbol> lookup(StringRef name) {
        return es->lookup({&main_jd}, name);
      }

      Expected<JITEvaluatedSymbol> lookup(SymbolStringPtr name) {
        return es->lookup({&main_jd}, name);
      }

      static void handle_lazy_call_through_error() {
        errs() << "LazyCallThrough error: Could not find function body";
        exit(1);
      }

      static Expected<jit_t*> make() {
        auto epc = SelfExecutorProcessControl::Create();
        if (!epc) {
          return epc.takeError();
        }

        auto es = std::make_unique<ExecutionSession>(std::move(*epc));

        auto epciu = EPCIndirectionUtils::Create(es->getExecutorProcessControl());
        if (!epciu) {
          return epciu.takeError();
        }

        (*epciu)->createLazyCallThroughManager(
          *es, pointerToJITTargetAddress(&handle_lazy_call_through_error));

        if (auto err = setUpInProcessLCTMReentryViaEPCIU(**epciu)) {
          return std::move(err);
        }

        JITTargetMachineBuilder jtmb(es->getExecutorProcessControl().getTargetTriple());

        auto tm = jtmb.createTargetMachine();
        if (!tm) {
          return tm.takeError();
        }

        auto dl = jtmb.getDefaultDataLayoutForTarget();
        if (!dl) {
          return dl.takeError();
        }

        return new jit_t(
          std::move(es)
        , std::move(*epciu)
        , std::move(jtmb)
        , std::move(*dl));
      }

      static Expected<ThreadSafeModule>
      optimize_module(ThreadSafeModule TSM, const MaterializationResponsibility &R) {
        TSM.withModuleDo([](Module &M) {
          // Create a function pass manager.
          auto FPM = std::make_unique<legacy::FunctionPassManager>(&M);

          // Add some optimizations.
          FPM->add(createInstructionCombiningPass());
          FPM->add(createReassociatePass());
          FPM->add(createGVNPass());
          FPM->add(createCFGSimplificationPass());
          FPM->doInitialization();

          // Run the optimizations over all functions in the module being added to
          // the JIT.
          for (auto &F : M) {
            FPM->run(F);
          }
        });

        return std::move(TSM);
      }
    };

    mat_unit_t::mat_unit_t(ast_layer_t& layer, const std::string& name, emit_t emit)
      : MaterializationUnit(layer.interface(name, emit))
      , layer(layer)
      , name(name)
      , emit(emit)
    {}

    void mat_unit_t::materialize(std::unique_ptr<MaterializationResponsibility> r) {
      layer.emit(std::move(r), std::move(emit));
    }
  }
}

using namespace llvm;
using namespace llvm::orc;

DEFINE_SIMPLE_CONVERSION_FUNCTIONS(llvm::orc::ThreadSafeModule, LLVMOrcThreadSafeModuleRef)

extern "C" {
  void* init() {
    InitializeNativeTargetAsmPrinter();
    InitializeNativeTargetAsmParser();
    InitializeNativeTarget();
    // InitializeNativeTargetTargetMC();

    auto jit = llvm::orc::jit_t::make();
    if (!jit) {
      std::cout << "Error: " << toString(std::move(jit.takeError())) << std::endl;
    }

    return jit.get();
  }

  void fini(void* jit) {
    delete static_cast<llvm::orc::jit_t*>(jit);
  }

  void add_module(void* jit, LLVMModuleRef module) {
    std::unique_ptr<llvm::Module> m(llvm::unwrap(module));

    ThreadSafeContext ctx(std::make_unique<LLVMContext>());
    ThreadSafeModule  tsm(std::move(m), ctx);

    if (auto error = static_cast<llvm::orc::jit_t*>(jit)->add(std::move(tsm))) {
      std::cout 
        << "Error while adding module: "
        << llvm::toString(std::move(error)) << std::endl;
    }

    // std::string s;
    // raw_string_ostream os(s);
    // static_cast<llvm::orc::jit_t*>(jit)->main_jd.dump(os);
    // std::cout << s << std::endl;
  }

  void add_ast(void* jit, const char* name, llvm::orc::mat_unit_t::emit_t emit) {
    if (auto error = static_cast<llvm::orc::jit_t*>(jit)->add(name, emit)) {
      std::cout 
        << "Error while adding function AST: " 
        << llvm::toString(std::move(error)) << std::endl;
    }
  }

  uint64_t lookup(void* jit, const char* name) {
    auto resolved = static_cast<llvm::orc::jit_t*>(jit)->lookup(name);

    if (!resolved) {
      std::cout 
        << "Unresolved symbol: " << name 
        << " (" << llvm::toString(resolved.takeError()) << ")" << std::endl;
    }

    return resolved ? resolved.get().getAddress() : 0;
  }
}

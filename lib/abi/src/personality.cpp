/**
 * Torque project exception ABI
 * Copyright 2016 Jan Krüger
 *
 */

#include <exception>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unwind.h>

enum {
  DW_EH_PE_absptr   = 0x00,
  DW_EH_PE_uleb128  = 0x01,
  DW_EH_PE_udata2   = 0x02,
  DW_EH_PE_udata4   = 0x03,
  DW_EH_PE_udata8   = 0x04,
  DW_EH_PE_sleb128  = 0x09,
  DW_EH_PE_sdata2   = 0x0A,
  DW_EH_PE_sdata4   = 0x0B,
  DW_EH_PE_sdata8   = 0x0C,
  DW_EH_PE_pcrel    = 0x10,
  DW_EH_PE_textrel  = 0x20,
  DW_EH_PE_datarel  = 0x30,
  DW_EH_PE_funcrel  = 0x40,
  DW_EH_PE_aligned  = 0x50,
  DW_EH_PE_indirect = 0x80,
  DW_EH_PE_omit     = 0xFF
};

struct __trq_scan_result {
  _Unwind_Reason_Code reason;
  const uint8_t*      action;
  uintptr_t           landing_pad;
};

struct __trq_exception {
  __trq_scan_result search_result;
  _Unwind_Exception	unwindHeader;
};

static uintptr_t read_uleb128(const uint8_t** data) {
  uintptr_t result = 0, shift = 0;
  unsigned char byte;
  const uint8_t* p = *data;
  do {
    byte = *p++;
    result |= static_cast<uintptr_t>(byte & 0x7F) << shift;
    shift += 7;
  } while(byte & 0x80);
  *data = p;
  return result;
}

static intptr_t read_sleb128(const uint8_t** data) {
  uintptr_t result = 0, shift = 0;
  unsigned char byte;
  const uint8_t* p = *data;
  do {
    byte = *p++;
    result |= static_cast<uintptr_t>(byte & 0x7F) << shift;
    shift += 7;
  } while(byte & 0x80);
  *data = p;
  if ((byte & 0x40) && (shift < (sizeof(result) << 3))) {
    result |= static_cast<uintptr_t>(~0) << shift;
  }
  return static_cast<intptr_t>(result);
}

template <class T>
uintptr_t read_ptr(const uint8_t*& p) {
  T value;
  memcpy(&value, p, sizeof(T));
  p += sizeof(T);
  return static_cast<uintptr_t>(value);
}

static uintptr_t read_ptr(const uint8_t** data, uint8_t encoding) {
  uintptr_t result = 0;
  if (encoding == DW_EH_PE_omit) {
    return result;
  }
  const uint8_t* p = *data;
  switch (encoding & 0x0F) {
  case DW_EH_PE_absptr:
    result = read_ptr<uintptr_t>(p);
    break;
  case DW_EH_PE_uleb128:
    result = read_uleb128(&p);
    break;
  case DW_EH_PE_sleb128:
    result = static_cast<uintptr_t>(read_sleb128(&p));
    break;
  case DW_EH_PE_udata2:
    result = read_ptr<uint16_t>(p);
    break;
  case DW_EH_PE_udata4:
    result = read_ptr<uint32_t>(p);
    break;
  case DW_EH_PE_udata8:
    result = read_ptr<uint64_t>(p);
    break;
  case DW_EH_PE_sdata2:
    result = read_ptr<int16_t>(p);
    break;
  case DW_EH_PE_sdata4:
    result = read_ptr<int32_t>(p);
    break;
  case DW_EH_PE_sdata8:
    result = read_ptr<int64_t>(p);
    break;
  default:
    printf("Unsupported encoding in read_ptr\n");
    abort();
    break;
  }

  switch (encoding & 0x70)
    {
    case DW_EH_PE_absptr:
      // do nothing 
      break;
    case DW_EH_PE_pcrel:
      if (result)
        result += (uintptr_t)(*data);
      break;
    case DW_EH_PE_textrel:
    case DW_EH_PE_datarel:
    case DW_EH_PE_funcrel:
    case DW_EH_PE_aligned:
    default:
      printf("Unsupported encoding in read_ptr\n");
      abort();
      break;
    }
  // then apply indirection 
  if (result && (encoding & DW_EH_PE_indirect)) {
    result = *((uintptr_t*)result);
  }
  *data = p;
  return result;
}

static void scan_handler_table(
  __trq_scan_result& result,
  _Unwind_Action     actions,
  _Unwind_Exception* unwind_exception,
  _Unwind_Context*   context) {
  const uint8_t* lsda = (const uint8_t*) _Unwind_GetLanguageSpecificData(context);
  if (lsda == 0) {
    result.reason = _URC_CONTINUE_UNWIND;
    return;
  }
  uintptr_t ip         = _Unwind_GetIP(context) - 1;
  uintptr_t func_start = _Unwind_GetRegionStart(context);
  uintptr_t offset     = ip - func_start;

  uint8_t lp_start_encoding = *lsda++;
  auto    lp_start = (const uint8_t*) read_ptr(&lsda, lp_start_encoding);
  if (lp_start == 0) {
    lp_start = (const uint8_t*) func_start;
  }

  uint8_t ttype_encoding = *lsda++;
  if (ttype_encoding != DW_EH_PE_omit) {
    uintptr_t class_info_offset = read_uleb128(&lsda);
  }

  uint8_t  call_site_encoding     = *lsda++;
  uint32_t call_site_table_length = static_cast<uint32_t>(read_uleb128(&lsda));

  const uint8_t* call_site_table_start = lsda;
  const uint8_t* call_site_table_end   = call_site_table_start +
    call_site_table_length;
  const uint8_t* action_table_start    = call_site_table_end;
  const uint8_t* call_site             = call_site_table_start;
  while (call_site < call_site_table_end) {
    uintptr_t start        = read_ptr(&call_site, call_site_encoding);
    uintptr_t length       = read_ptr(&call_site, call_site_encoding);
    uintptr_t landing_pad  = read_ptr(&call_site, call_site_encoding);
    uintptr_t action_entry = read_uleb128(&call_site);
    if ((start <= offset) && (offset < (start + length))) {
      if (landing_pad == 0) {
        result.reason = _URC_CONTINUE_UNWIND;
        return;
      }
      landing_pad = (uintptr_t) lp_start + landing_pad;
      if (action_entry == 0) {
        if ((actions && _UA_CLEANUP_PHASE) && !(actions & _UA_HANDLER_FRAME)) {
          result.landing_pad = landing_pad;
          result.reason      = _URC_HANDLER_FOUND;
          return;
        }
        result.reason = _URC_CONTINUE_UNWIND;
        return;
      }
      const uint8_t* action = action_table_start + (action_entry - 1);
      while (true) {
        const uint8_t* action_record = action;
        int64_t type_index = read_sleb128(&action);
        // there are no catch type specifications so we always catch
        // everything, except foreign exceptions
        if (type_index == 0) {
          // TODO: cleanup
        }
        else {
          if ((actions & _UA_SEARCH_PHASE) || (actions & _UA_HANDLER_FRAME)) {
            result.landing_pad = landing_pad;
            result.action      = action_record;
            result.reason      = _URC_HANDLER_FOUND;
            return;
          }
          else if (!(actions & _UA_FORCE_UNWIND)) {
            printf("!(actions & _UA_FORCE_UNWIND)\n");
            abort();
          }
        }
        const uint8_t* tmp = action;
        int64_t action_offset = read_sleb128(&tmp);
        if (action_offset == 0) {
          result.reason = _URC_CONTINUE_UNWIND;
        }
        action += action_offset;
      }
    }
    if (offset < start) {
      std::terminate();
    }
  }
  std::terminate();
}

static void set_registers(
  _Unwind_Exception* unwind_exception, _Unwind_Context* context,
  const __trq_scan_result& result) {
  _Unwind_SetGR(
    context, __builtin_eh_return_data_regno(0),
    reinterpret_cast<uintptr_t>(unwind_exception));
  // _Unwind_SetGR(
  //   context, __builtin_eh_return_data_regno(1),
  //   static_cast<uintptr_t>(result.ttypeIndex));
  _Unwind_SetIP(context, result.landing_pad);
}

extern "C" {

static __trq_exception __trq_ex;

void __trq_throw(void* exception) {
  __trq_ex.unwindHeader.exception_class = 0xdeadbeef;
  _Unwind_RaiseException(&__trq_ex.unwindHeader);
  exit(-1);
}

_Unwind_Reason_Code __trq_personality_v0(
  int version,
  _Unwind_Action actions,
  uint64_t exception_class,
  struct _Unwind_Exception* ex,
  struct _Unwind_Context* context) {

  if (ex->exception_class != 0xdeadbeef) {
    printf("Foreign exception\n");
    std::terminate();
  }
  else {
    printf("torque exception found\n");
  }

  if (actions & _UA_SEARCH_PHASE) {
    printf("Personality function, lookup phase\n");
    // search for an exception handler
    scan_handler_table(__trq_ex.search_result, actions, ex, context);
    if (__trq_ex.search_result.reason == _URC_HANDLER_FOUND) {
      // TODO: cache data we need in later phases
      return _URC_HANDLER_FOUND;
    }
    return __trq_ex.search_result.reason;
  }
  else if (actions & _UA_CLEANUP_PHASE) {
    printf("Personality function, cleanup\n");
    if (actions & _UA_HANDLER_FRAME) {
      // TODO: load cached scan result
      set_registers(ex, context, __trq_ex.search_result);
      return _URC_INSTALL_CONTEXT;
    }
    return __trq_ex.search_result.reason;
  }
  else {
    printf("Personality function, error\n");
    return _URC_FATAL_PHASE1_ERROR;
  }
}
}

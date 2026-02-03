// LZInWindow.h

#ifndef __LZ_IN_WINDOW_H
#define __LZ_IN_WINDOW_H

// This is needed because CLZInWindow::_buffer is a pointer to
// the VIRTUAL buffer begin, and it can actually wrap.
//
// Note that we are compiling with -fno-strict-overflow (which includes
// -fwrapv-pointer), but gcc seems to ignore that.
#if __has_attribute(__no_sanitize__)
#define LZMA_NO_UBSAN_POINTER_WRAP __attribute__((__no_sanitize__("undefined")))
#elif __has_attribute(__no_sanitize_undefined__)
#define LZMA_NO_UBSAN_POINTER_WRAP __attribute__((__no_sanitize_undefined__))
#else
#define LZMA_NO_UBSAN_POINTER_WRAP /*empty*/
#endif

#include "../../IStream.h"

class CLZInWindow /*not_final*/
{
  Byte *_bufferBase; // pointer to buffer with data
  ISequentialInStream *_stream;
  UInt32 _posLimit;  // offset (from _buffer) when new block reading must be done
  bool _streamEndWasReached; // if (true) then _streamPos shows real end of stream
  const Byte *_pointerToLastSafePosition;
protected:
  Byte  *_buffer;   // Pointer to virtual Buffer begin
  UInt32 _blockSize;  // Size of Allocated memory block
  UInt32 _pos;             // offset (from _buffer) of curent byte
  UInt32 _keepSizeBefore;  // how many BYTEs must be kept in buffer before _pos
  UInt32 _keepSizeAfter;   // how many BYTEs must be kept buffer after _pos
  UInt32 _streamPos;   // offset (from _buffer) of first not read byte from Stream

  void MoveBlock();
  HRESULT ReadBlock();
  void Free();
public:
  CLZInWindow(): _bufferBase(NULL) {} // NOLINT(clang-analyzer-optin.cplusplus.UninitializedObject)
  virtual ~CLZInWindow() { Free(); }

  // keepSizeBefore + keepSizeAfter + keepSizeReserv < 4G)
  bool Create(UInt32 keepSizeBefore, UInt32 keepSizeAfter, UInt32 keepSizeReserv = (1<<17));

  void SetStream(ISequentialInStream *stream);
  HRESULT Init();
  // void ReleaseStream();

  Byte *GetBuffer() const = delete; // { return _buffer; }

  LZMA_NO_UBSAN_POINTER_WRAP
  const Byte *GetPointerToCurrentPos() const { return _buffer + _pos; }

  LZMA_NO_UBSAN_POINTER_WRAP
  HRESULT MovePos()
  {
    _pos++;
    if (_pos > _posLimit)
    {
      const Byte *pointerToPostion = _buffer + _pos;
      if(pointerToPostion > _pointerToLastSafePosition)
        MoveBlock();
      return ReadBlock();
    }
    else
      return S_OK;
  }

  LZMA_NO_UBSAN_POINTER_WRAP
  Byte GetIndexByte(Int32 index) const  {  return _buffer[(size_t)_pos + index]; }

  // index + limit have not to exceed _keepSizeAfter;
  // -2G <= index < 2G
  LZMA_NO_UBSAN_POINTER_WRAP
  UInt32 GetMatchLen(Int32 index, UInt32 distance, UInt32 limit) const
  {
    if(_streamEndWasReached)
      if ((_pos + index) + limit > _streamPos)
        limit = _streamPos - (_pos + index);
    distance++;
    const Byte *pby = _buffer + (size_t)_pos + index;
    UInt32 i;
    for(i = 0; i < limit && pby[i] == pby[(size_t)i - distance]; i++) { }
    return i;
  }

  UInt32 GetNumAvailableBytes() const { return _streamPos - _pos; }

  LZMA_NO_UBSAN_POINTER_WRAP
  void ReduceOffsets(Int32 subValue)
  {
    _buffer += subValue;
    _posLimit -= subValue;
    _pos -= subValue;
    _streamPos -= subValue;
  }

  LZMA_NO_UBSAN_POINTER_WRAP
  bool NeedMove(UInt32 numCheckBytes)
  {
    size_t reserv = _pointerToLastSafePosition - (_buffer + _pos);
    return (reserv <= numCheckBytes);
  }
};

#endif

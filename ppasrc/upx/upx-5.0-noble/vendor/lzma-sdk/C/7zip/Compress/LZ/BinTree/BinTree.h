// BinTree.h

#include "../LZInWindow.h"
#include "../IMatchFinder.h"

namespace BT_NAMESPACE {

typedef UInt32 CIndex;
const UInt32 kMaxValForNormalize = (UInt32(1) << 31) - 1;

class CMatchFinder final :
  public IMatchFinder,
  public CLZInWindow,
  public CMyUnknownImp,
  public IMatchFinderSetNumPasses
{
  UInt32 _cyclicBufferPos;
  UInt32 _cyclicBufferSize; // it must be historySize + 1
  UInt32 _matchMaxLen;
  CIndex *_hash;
  CIndex *_son;
#if !defined(BT_NO_HASH_MASK)
  UInt32 _hashMask;
#endif
  UInt32 _cutValue;
  UInt32 _hashSizeSum;

  void Normalize();
  void FreeThisClassMemory();
  void FreeMemory();

  MY_UNKNOWN_IMP

  STDMETHOD(SetStream)(ISequentialInStream *inStream) override;
  STDMETHOD_(void, ReleaseStream)() override;
  STDMETHOD(Init)() override;
  HRESULT MovePos();
  STDMETHOD_(Byte, GetIndexByte)(Int32 index) override;
  STDMETHOD_(UInt32, GetMatchLen)(Int32 index, UInt32 back, UInt32 limit) override;
  STDMETHOD_(UInt32, GetNumAvailableBytes)() override;
  STDMETHOD_(const Byte *, GetPointerToCurrentPos)() override;
  STDMETHOD_(Int32, NeedChangeBufferPos)(UInt32 numCheckBytes) override;
  STDMETHOD_(void, ChangeBufferPos)() override;

  STDMETHOD(Create)(UInt32 historySize, UInt32 keepAddBufferBefore,
      UInt32 matchMaxLen, UInt32 keepAddBufferAfter) override;
  STDMETHOD(GetMatches)(UInt32 *distances) override;
  STDMETHOD(Skip)(UInt32 num) override;

public:
  CMatchFinder();
  virtual ~CMatchFinder();
  virtual void SetNumPasses(UInt32 numPasses) override { _cutValue = numPasses; }
};

}

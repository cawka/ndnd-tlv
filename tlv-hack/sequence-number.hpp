/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * See COPYING for copyright and distribution information.
 */

#ifndef TLV_HACK_SEQUENCE_NUMBER_HPP
#define TLV_HACK_SEQUENCE_NUMBER_HPP

#include <ndn-cxx/encoding/encoding-buffer.hpp>

namespace ndn {

class SequenceNumber {
public:
  struct Error : public Tlv::Error { Error(const std::string &what) : Tlv::Error(what) {} };

  enum {
    TlvType = 80
  };

  SequenceNumber ()
    : m_sequenceNumber(0)
  {
  }

  SequenceNumber(const Block& block)
  {
    wireDecode(block);
  }

  void
  setSequenceNumber(uint64_t sequenceNumber)
  {
    m_sequenceNumber = sequenceNumber;
  }

  uint64_t
  getSequenceNumber() const
  {
    return m_sequenceNumber;
  }

  template<bool T>
  size_t
  wireEncode(EncodingImpl<T> &block) const;

  const Block&
  wireEncode () const;

  void
  wireDecode (const Block &wire);

private:
  uint64_t m_sequenceNumber;

  mutable Block m_wire;
};


template<bool T>
inline size_t
SequenceNumber::wireEncode(EncodingImpl<T>& blk) const
{
  // SequenceNumber ::= SEQUENCE-NUMBER-TYPE TLV-LENGTH
  //                      nonNegativeInteger

  size_t total_len = 0;

  total_len += blk.prependNonNegativeInteger(m_sequenceNumber);
  total_len += blk.prependVarNumber(total_len);
  total_len += blk.prependVarNumber(TlvType);
  return total_len;
}

inline const Block&
SequenceNumber::wireEncode () const
{
  if (m_wire.hasWire ())
    return m_wire;

  EncodingEstimator estimator;
  size_t estimatedSize = wireEncode(estimator);

  EncodingBuffer buffer(estimatedSize, 0);
  wireEncode(buffer);

  m_wire = buffer.block();
  return m_wire;
}

inline void
SequenceNumber::wireDecode (const Block &wire)
{
  m_wire = wire;

  if (m_wire.type() != TlvType)
    throw Error("Requested decoding of SequenceNumber, but Block is of different type");

  m_wire.parse ();

  m_sequenceNumber = readNonNegativeInteger(m_wire);
}

} // namespace ndn

#endif // TLV_HACK_SEQUENCE_NUMBER_HPP

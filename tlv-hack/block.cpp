/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "block.hpp"

#include "tlv.hpp"

namespace ndn {

Block::Block()
  : m_type(std::numeric_limits<uint32_t>::max())
{
}

Block::Block(const ConstBufferPtr &wire,
             uint32_t type,
             const Buffer::const_iterator &begin, Buffer::const_iterator &end,
             const Buffer::const_iterator &valueBegin, Buffer::const_iterator &valueEnd)
  : m_buffer(wire)
  , m_type(type)
  , m_begin(begin)
  , m_end(end)
  , m_value_begin(valueBegin)
  , m_value_end(valueEnd)
{
}

Block::Block(const ConstBufferPtr &buffer)
  : m_buffer(buffer)
  , m_begin(m_buffer->begin())
  , m_end(m_buffer->end())
{
  m_value_begin = m_buffer->begin();
  m_value_end   = m_buffer->end();
  
  m_type = Tlv::readType(m_value_begin, m_value_end);

  uint64_t length = Tlv::readVarNumber(m_value_begin, m_value_end);
  if (length != (m_value_end - m_value_begin))
    {
      throw new Tlv::Error("TLV length doesn't match buffer length");
    }
}

Block::Block(const uint8_t *buffer, size_t maxlength)
{
  const uint8_t * tmp_begin = buffer;
  const uint8_t * tmp_end   = buffer + maxlength;  
  
  m_type = Tlv::readType(tmp_begin, tmp_end);
  uint64_t length = Tlv::readVarNumber(tmp_begin, tmp_end);
  
  if (length > (tmp_end - tmp_begin))
    {
      throw new Tlv::Error("Not enough data in the buffer to fully parse TLV");
    }

  m_buffer = ptr_lib::make_shared<Buffer> (buffer, (tmp_begin - buffer) + length);

  m_begin = m_buffer->begin();
  m_end = m_buffer->end();

  m_value_begin = m_buffer->begin() + (tmp_begin - buffer);
  m_value_end   = m_buffer->end();
}

Block::Block(uint32_t type)
  : m_type(type)
{
}

Block::Block(uint32_t type, const ConstBufferPtr &value)
  : m_type(type)
  , m_buffer(value)
  , m_begin()
  , m_end()
  , m_value_begin(value->begin())
  , m_value_end(value->end())
{
}

void
Block::parse()
{
  Buffer::const_iterator begin = value_begin(),
    end = value_end();

  while (begin != end)
    {
      Buffer::const_iterator element_begin = begin;
      
      uint32_t type = Tlv::readType(begin, end);
      uint64_t length = Tlv::readVarNumber(begin, end);

      if (end-begin < length)
        {
          throw new Tlv::Error("TLV length exceeds buffer length");
        }
      Buffer::const_iterator element_end = begin + length;
      
      m_subBlocks.push_back(Block(m_buffer,
                                  type,
                                  element_begin, element_end,
                                  begin, end));
      
      // don't do recursive parsing, just the top level
    }
}

} // namespace ndn

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef NDN_BLOCK_HPP
#define NDN_BLOCK_HPP

#include "common.hpp"

#include <list>
#include <exception>

#include "buffer.hpp"

namespace ndn {

/**
 * @brief Class representing wire element of the NDN packet
 */
class Block
{
public:
  typedef std::list<Block>::iterator element_iterator;
  typedef std::list<Block>::const_iterator element_const_iterator;

  /// @brief Error that can be thrown from the block
  struct Error : public std::runtime_error { Error(const std::string &what) : std::runtime_error(what) {} };
  
  /**
   * @brief Default constructor to create an empty Block
   */
  Block();

  /**
   * @brief A helper version of a constructor to create Block from the raw buffer (type and value-length parsing)
   */
  Block(const ConstBufferPtr &buffer);

  /**
   * @brief A helper version of a constructor to create Block from the raw buffer (type and value-length parsing)
   */
  Block(const uint8_t *buffer, size_t maxlength);
  
  /**
   * @brief Create Block from the wire buffer (no parsing)
   *
   * This version of the constructor does not do any parsing
   */
  Block(const ConstBufferPtr &wire,
        uint32_t type,
        const Buffer::const_iterator &begin, Buffer::const_iterator &end,
        const Buffer::const_iterator &valueBegin, Buffer::const_iterator &valueEnd);

  /**
   * @brief Create Block of a specific type with empty wire buffer
   */
  Block(uint32_t type);

  /**
   * @brief Create Block of a specific type with the specified value
   *
   * The underlying buffer hold only value, additional operations are needed
   * to construct wire encoding, one need to prepend the wire buffer with type
   * and value-length VAR-NUMBERs
   */
  Block(uint32_t type, const ConstBufferPtr &value);

  /**
   * @brief Check if the Block has fully encoded wire
   */
  inline bool
  hasWire() const;

  /**
   * @brief Check if the Block has value block (no type and length are encoded)
   */
  inline bool
  hasValue() const;
  
  /**
   * @brief Reset wire buffer of the element
   */
  inline void
  reset();

  void
  parse();
  
  inline uint32_t
  type() const;

  /**
   * @brief Get the first subelement of the requested type
   */
  inline const Block &
  get(uint32_t type) const;

  inline Block &
  get(uint32_t type);
  
  inline element_iterator
  find(uint32_t type);

  inline element_const_iterator
  find(uint32_t type) const;
  
  /**
   * @brief Get all subelements
   */
  inline const std::list<Block>&
  getAll () const;

  inline std::list<Block>&
  getAll ();
  
  /**
   * @brief Get all elements of the requested type
   */
  std::list<Block>
  getAll(uint32_t type) const;

  inline Buffer::const_iterator
  begin() const;

  inline Buffer::const_iterator
  end() const;

  inline size_t
  size() const;

  inline Buffer::const_iterator
  value_begin() const;

  inline Buffer::const_iterator
  value_end() const;

  inline const uint8_t*
  value() const;

  inline size_t
  value_size() const;

protected:
  ConstBufferPtr m_buffer;

  uint32_t m_type;
  Buffer::const_iterator m_begin;
  Buffer::const_iterator m_end;
  
  Buffer::const_iterator m_value_begin;
  Buffer::const_iterator m_value_end;

  std::list<Block> m_subBlocks;
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

inline bool
Block::hasWire() const
{
  if (static_cast<bool> (m_buffer)) {
    return m_begin != Buffer::const_iterator();
  }
  else
    return false;
}

inline bool
Block::hasValue() const
{
  if (static_cast<bool> (m_buffer)) {
    return m_begin == Buffer::const_iterator();
  }
  else
    return false;
}

inline void
Block::reset()
{
  m_buffer.reset(); // reset of the shared_ptr
  m_subBlocks.clear(); // remove all parsed subelements

  m_type = std::numeric_limits<uint32_t>::max();
  m_begin = m_end = m_value_begin = m_value_end = Buffer::const_iterator(); // not really necessary, but for safety
}

inline uint32_t
Block::type() const
{
  return m_type;
}

inline const Block &
Block::get(uint32_t type) const
{
  for (element_const_iterator i = m_subBlocks.begin ();
       i != m_subBlocks.end();
       i++)
    {
      if (i->type () == type)
        {
          return *i;
        }
    }
  throw new Error("Requested a non-existed type from Block");
}

inline Block &
Block::get(uint32_t type)
{
  for (element_iterator i = m_subBlocks.begin ();
       i != m_subBlocks.end();
       i++)
    {
      if (i->type () == type)
        {
          return *i;
        }
    }
  throw new Error("Requested a non-existed type from Block");
}
  
inline Block::element_const_iterator
Block::find(uint32_t type) const
{
  for (element_const_iterator i = m_subBlocks.begin ();
       i != m_subBlocks.end();
       i++)
    {
      if (i->type () == type)
        {
          return i;
        }
    }
  return m_subBlocks.end();
}

inline Block::element_iterator
Block::find(uint32_t type)
{
  for (element_iterator i = m_subBlocks.begin ();
       i != m_subBlocks.end();
       i++)
    {
      if (i->type () == type)
        {
          return i;
        }
    }
  return m_subBlocks.end();
}


inline const std::list<Block>&
Block::getAll () const
{
  return m_subBlocks;
}

inline std::list<Block>&
Block::getAll ()
{
  return m_subBlocks;
}


inline Buffer::const_iterator
Block::begin() const
{
  if (!hasWire())
      throw new Error("Underlying wire buffer is empty");

  return m_begin;
}

inline Buffer::const_iterator
Block::end() const
{
  if (!hasWire())
      throw new Error("Underlying wire buffer is empty");

  return m_end;
}

inline size_t
Block::size() const
{
  if (!hasWire())
      throw new Error("Underlying wire buffer is empty");

  return m_end - m_begin;
}

inline Buffer::const_iterator
Block::value_begin() const
{
  if (!hasValue())
      throw new Error("Underlying value buffer is empty");

  return m_value_begin;
}

inline Buffer::const_iterator
Block::value_end() const
{
  if (!hasValue())
      throw new Error("Underlying value buffer is empty");

  return m_value_end;
}


inline const uint8_t*
Block::value() const
{
  if (!hasValue())
      throw new Error("Underlying value buffer is empty");
  
  return &*m_value_begin;
}

inline size_t
Block::value_size() const
{
  if (!hasValue())
    throw new Error("Underlying value buffer is empty");

  return m_value_end - m_value_begin;
}

} // ndn

#endif // NDN_BLOCK_HPP

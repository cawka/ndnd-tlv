/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef NDN_TLV_ELEMENT_HPP
#define NDN_TLV_ELEMENT_HPP

#include "common.hpp"

#include <list>
#include <exception>

#include "tlv.hpp"
#include "buffer.hpp"

namespace ndn {

namespace error {
namespace tlv {
struct Element : public std::runtime_error { Element(const std::string &what) : std::runtime_error(what) {} };
} // tlv
} // error

namespace tlv {

/**
 * @brief Class representing wire element of the NDN packet
 */
class Element
{
public:
  typedef std::list<Element>::iterator element_iterator;
  typedef std::list<Element>::const_iterator element_const_iterator;
  
  /**
   * @brief Default constructor to create an empty element (empty wire buffer)
   */
  Element();

  Element(const ptr_lib::shared_ptr<const Buffer> &buffer);

  /**
   * @brief A helper version of a constructor to create tlv::Element from the raw buffer
   */
  Element(const uint8_t *buffer, size_t maxlength);
  
  /**
   * @brief Create element from the wire buffer
   *
   * This constructor will attempt to parse and index the top level elements
   * in the supplied wire buffer
   *
   * @param rootElementBuffer shared pointer to the buffer storing the root element of the wire block
   */
  Element(const ptr_lib::shared_ptr<const Buffer> &rootElementBuffer,
          uint32_t type,
          const Buffer::const_iterator &begin, Buffer::const_iterator &end,
          const Buffer::const_iterator &valueBegin, Buffer::const_iterator &valueEnd);

  /**
   * @brief Check if the underlying wire buffer is set
   */
  inline
  operator bool() const;

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
  inline const Element &
  get(uint32_t type) const;

  inline Element &
  get(uint32_t type);
  
  inline element_iterator
  find(uint32_t type);

  inline element_const_iterator
  find(uint32_t type) const;
  
  /**
   * @brief Get all subelements
   */
  inline const std::list<Element>&
  getAll () const;

  inline std::list<Element>&
  getAll ();
  
  /**
   * @brief Get all elements of the requested type
   */
  std::list<Element>
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
  ptr_lib::shared_ptr<const Buffer> m_buffer;

  uint32_t m_type;
  Buffer::const_iterator m_begin;
  Buffer::const_iterator m_end;
  
  Buffer::const_iterator m_value_begin;
  Buffer::const_iterator m_value_end;

  std::list<Element> m_subElements;
};


Element::operator bool() const
{
  return static_cast<bool> (m_buffer);
}

void
Element::reset()
{
  m_buffer.reset(); // reset of the shared_ptr
  m_subElements.clear(); // remove all parsed subelements

  m_type = std::numeric_limits<uint32_t>::max();
  m_begin = m_end = m_value_begin = m_value_end = Buffer::const_iterator(); // not really necessary, but for safety
}

inline uint32_t
Element::type() const
{
  return m_type;
}

inline const Element &
Element::get(uint32_t type) const
{
  for (element_const_iterator i = m_subElements.begin ();
       i != m_subElements.end();
       i++)
    {
      if (i->type () == type)
        {
          return *i;
        }
    }
  throw new error::tlv::Element("Requested a non-existed type from Element");
}

inline Element &
Element::get(uint32_t type)
{
  for (element_iterator i = m_subElements.begin ();
       i != m_subElements.end();
       i++)
    {
      if (i->type () == type)
        {
          return *i;
        }
    }
  throw new error::tlv::Element("Requested a non-existed type from Element");
}
  
inline Element::element_const_iterator
Element::find(uint32_t type) const
{
  for (element_const_iterator i = m_subElements.begin ();
       i != m_subElements.end();
       i++)
    {
      if (i->type () == type)
        {
          return i;
        }
    }
  return m_subElements.end();
}

inline Element::element_iterator
Element::find(uint32_t type)
{
  for (element_iterator i = m_subElements.begin ();
       i != m_subElements.end();
       i++)
    {
      if (i->type () == type)
        {
          return i;
        }
    }
  return m_subElements.end();
}


inline const std::list<Element>&
Element::getAll () const
{
  return m_subElements;
}

inline std::list<Element>&
Element::getAll ()
{
  return m_subElements;
}


inline Buffer::const_iterator
Element::begin() const
{
  return m_begin;
}

inline Buffer::const_iterator
Element::end() const
{
  return m_end;
}

inline size_t
Element::size() const
{
  return m_buffer->size();
}

inline Buffer::const_iterator
Element::value_begin() const
{
  return m_value_begin;
}

inline Buffer::const_iterator
Element::value_end() const
{
  return m_value_end;
}


inline const uint8_t*
Element::value() const
{
  if (!*this)
    {
      throw new error::tlv::Element("Underlying wire buffer is empty");
    }
  
  return &*m_value_begin;
}

inline size_t
Element::value_size() const
{
  if (!*this)
    {
      throw new error::tlv::Element("Underlying wire buffer is empty");
    }
  return m_value_end - m_value_begin;
}

} // tlv
} // ndn

#endif // NDN_TLV_ELEMENT_HPP

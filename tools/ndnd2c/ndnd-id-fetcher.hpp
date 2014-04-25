/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * See COPYING for copyright and distribution information.
 */

#ifndef NDN_NDND_ID_FETCHER_HPP
#define NDN_NDND_ID_FETCHER_HPP

#include <ndn-cxx/common.hpp>
#include <ndn-cxx/util/crypto.hpp>

namespace ndn {

/**
 * An NdndIdFetcher receives the Data packet with the publisher public key digest for the connected NDN hub.
 * This class is a function object for the callbacks. It only holds a pointer to an Info object, so it is OK to copy the pointer.
 */
class NdndIdFetcher {
public:
  typedef func_lib::function<void (void)> OnSuccess;
  typedef func_lib::function<void (void)> OnFailure;


  class Info;
  NdndIdFetcher(Buffer &ndndId, const OnSuccess& onSuccess, const OnFailure& onFailure)
    : ndndId_(ndndId)
    , onSuccess_(onSuccess)
    , onFailure_(onFailure)
  {
  }

  /**
   * We received the ndnd ID.
   * @param interest
   * @param data
   */
  inline void
  operator()(const Interest& interest, Data& ndndIdData);

  /**
   * We timed out fetching the ndnd ID.
   * @param interest
   */
  inline void
  operator()(const Interest& timedOutInterest);

private:
  Buffer &ndndId_;
  OnSuccess onSuccess_;
  OnFailure onFailure_;
};

void
NdndIdFetcher::operator()(const Interest& interest, Data& ndndIdData)
{
  if (ndndIdData.getSignature().getType() == Signature::Sha256WithRsa)
    {
      ndndId_.resize(32);
      ndn_digestSha256(ndndIdData.getContent().value(), ndndIdData.getContent().value_size(), ndndId_.buf());
      onSuccess_();
    }
  else
    onFailure_();
}

void
NdndIdFetcher::operator()(const Interest& timedOutInterest)
{
  onFailure_();
}


} // namespace ndn

#endif // NDN_NDND_ID_FETCHER_HPP

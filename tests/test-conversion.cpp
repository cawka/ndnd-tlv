/**
 * Copyright (C) 2013 Regents of the University of California.
 * See COPYING for copyright and distribution information.
 */

#include <boost/test/unit_test.hpp>

extern "C" {
#define ndn NDN_HANDLE_CANNOT_BE_USED_HERE
#include <ndn-tlv/ndnd.h>
#include <ndn-tlv/ndn.h>
#include <ndn-tlv/charbuf.h>
#include <ndn-tlv/coding.h>

#include "../ndnd/ndnd_private.h"
#undef ndn
}

#include "../tlv-hack/tlv-hack.h"
#include "../tlv-hack/ndnb-to-tlv.hpp"
#include "../tlv-hack/tlv-to-ndnb.hpp"

#include <fstream>


using namespace std;
namespace ndn {

BOOST_AUTO_TEST_SUITE(TestConversion)

const uint8_t DataTlv[] = {
0x06, 0xc5, // NDN Data                           
    0x07, 0x14, // Name                           
        0x08, 0x05,    
            0x6c, 0x6f, 0x63, 0x61, 0x6c,
        0x08, 0x03,    
            0x6e, 0x64, 0x6e,
        0x08, 0x06,    
            0x70, 0x72, 0x65, 0x66, 0x69, 0x78,
    0x14, 0x04, // MetaInfo
        0x19, 0x02, // FreshnessPeriod
            0x27, 0x10,               
    0x15, 0x08, // Content            
        0x53, 0x55, 0x43, 0x43, 0x45, 0x53, 0x53, 0x21,
    0x16, 0x1b, // SignatureInfo
        0x1b, 0x01, // SignatureType
            0x01,                   
        0x1c, 0x16, // KeyLocator
            0x07, 0x14, // Name  
                0x08, 0x04,    
                    0x74, 0x65, 0x73, 0x74,
                0x08, 0x03,    
                    0x6b, 0x65, 0x79,
                0x08, 0x07,    
                    0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72,
    0x17, 0x80, // SignatureValue
        0x2f, 0xd6, 0xf1, 0x6e, 0x80, 0x6f, 0x10, 0xbe, 0xb1, 0x6f, 0x3e, 0x31, 0xec, 0xe3, 0xb9, 0xea, 0x83, 0x30, 0x40, 0x03, 0xfc, 0xa0, 0x13, 0xd9, 0xb3, 0xc6, 0x25, 0x16, 0x2d, 0xa6, 0x58, 0x41, 0x69, 0x62, 0x56, 0xd8, 0xb3, 0x6a, 0x38, 0x76, 0x56, 0xea, 0x61, 0xb2, 0x32, 0x70, 0x1c, 0xb6, 0x4d, 0x10, 0x1d, 0xdc, 0x92, 0x8e, 0x52, 0xa5, 0x8a, 0x1d, 0xd9, 0x96, 0x5e, 0xc0, 0x62, 0x0b, 0xcf, 0x3a, 0x9d, 0x7f, 0xca, 0xbe, 0xa1, 0x41, 0x71, 0x85, 0x7a, 0x8b, 0x5d, 0xa9, 0x64, 0xd6, 0x66, 0xb4, 0xe9, 0x8d, 0x0c, 0x28, 0x43, 0xee, 0xa6, 0x64, 0xe8, 0x55, 0xf6, 0x1c, 0x19, 0x0b, 0xef, 0x99, 0x25, 0x1e, 0xdc, 0x78, 0xb3, 0xa7, 0xaa, 0x0d, 0x14, 0x58, 0x30, 0xe5, 0x37, 0x6a, 0x6d, 0xdb, 0x56, 0xac, 0xa3, 0xfc, 0x90, 0x7a, 0xb8, 0x66, 0x9c, 0x0e, 0xf6, 0xb7, 0x64, 0xd1
};

const uint8_t DataNdnb[] = {
  0x04, 0x82, 0x02, 0xaa, 0x03, 0xb2, 0x08, 0x85, 0x2f, 0xd6, 0xf1, 0x6e, 0x80, 0x6f, 0x10, 0xbe, 0xb1, 0x6f, 0x3e, 0x31, 0xec, 0xe3, 0xb9, 0xea, 0x83, 0x30, 0x40, 0x03, 0xfc, 0xa0, 0x13, 0xd9, 0xb3, 0xc6, 0x25, 0x16, 0x2d, 0xa6, 0x58, 0x41, 0x69, 0x62, 0x56, 0xd8, 0xb3, 0x6a, 0x38, 0x76, 0x56, 0xea, 0x61, 0xb2, 0x32, 0x70, 0x1c, 0xb6, 0x4d, 0x10, 0x1d, 0xdc, 0x92, 0x8e, 0x52, 0xa5, 0x8a, 0x1d, 0xd9, 0x96, 0x5e, 0xc0, 0x62, 0x0b, 0xcf, 0x3a, 0x9d, 0x7f, 0xca, 0xbe, 0xa1, 0x41, 0x71, 0x85, 0x7a, 0x8b, 0x5d, 0xa9, 0x64, 0xd6, 0x66, 0xb4, 0xe9, 0x8d, 0x0c, 0x28, 0x43, 0xee, 0xa6, 0x64, 0xe8, 0x55, 0xf6, 0x1c, 0x19, 0x0b, 0xef, 0x99, 0x25, 0x1e, 0xdc, 0x78, 0xb3, 0xa7, 0xaa, 0x0d, 0x14, 0x58, 0x30, 0xe5, 0x37, 0x6a, 0x6d, 0xdb, 0x56, 0xac, 0xa3, 0xfc, 0x90, 0x7a, 0xb8, 0x66, 0x9c, 0x0e, 0xf6, 0xb7, 0x64, 0xd1, 0x00, 0x00, 0xf2, 0xfa, 0xad, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0xfa, 0x9d, 0x6e, 0x64, 0x6e, 0x00, 0xfa, 0xb5, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x00, 0x00, 0x01, 0xa2, 0x03, 0xe2, 0x02, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xba, 0xad, 0x95, 0xce, 0xb8, 0x00, 0x00, 0x00, 0x03, 0xd2, 0x96, 0x31, 0x30, 0x00, 0x01, 0xe2, 0x01, 0xea, 0xf2, 0xfa, 0xa5, 0x74, 0x65, 0x73, 0x74, 0x00, 0xfa, 0x9d, 0x6b, 0x65, 0x79, 0x00, 0xfa, 0xbd, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x9a, 0xc5, 0x53, 0x55, 0x43, 0x43, 0x45, 0x53, 0x53, 0x21, 0x00, 0x00
};

BOOST_AUTO_TEST_CASE (TlvToNdnb)
{
  Block tlv(DataTlv, sizeof(DataTlv));
  ndn_charbuf *ndnb = ndn_charbuf_create();

  BOOST_REQUIRE_NO_THROW(data_tlv_to_ndnb(tlv, ndnb));

  BOOST_CHECK_EQUAL_COLLECTIONS(ndnb->buf, ndnb->buf + ndnb->length,
                                DataNdnb, DataNdnb + sizeof(DataNdnb));
  
  ndn_charbuf_destroy(&ndnb);
}

BOOST_AUTO_TEST_CASE (NdnbToTlv)
{
  uint8_t tlv[8800];
  ssize_t size = ndnb_to_tlv(DataNdnb, sizeof(DataNdnb), tlv, sizeof(tlv));

  BOOST_REQUIRE_GT(size, 0);
  BOOST_CHECK_EQUAL(size, sizeof(DataTlv));

  BOOST_CHECK_EQUAL_COLLECTIONS(tlv, tlv + size,
                                DataTlv, DataTlv + sizeof(DataTlv));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace ndn

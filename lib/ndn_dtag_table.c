/**
 * @file ndn_dtag_table.c
 * @brief DTAG table.
 * 
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2008-2012 Palo Alto Research Center, Inc.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details. You should have received
 * a copy of the GNU Lesser General Public License along with this library;
 * if not, write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <ndn-tlv/coding.h>

#define ARRAY_N(arr) (sizeof(arr)/sizeof(arr[0]))
/**
 * See the gen_dtag_table script for help updating these.
 */
static const struct ndn_dict_entry ndn_tagdict[] = {
    {NDN_DTAG_Any, "Any"},
    {NDN_DTAG_Name, "Name"},
    {NDN_DTAG_Component, "Component"},
    {NDN_DTAG_Certificate, "Certificate"},
    {NDN_DTAG_Collection, "Collection"},
    {NDN_DTAG_CompleteName, "CompleteName"},
    {NDN_DTAG_Content, "Content"},
    {NDN_DTAG_SignedInfo, "SignedInfo"},
    {NDN_DTAG_ContentDigest, "ContentDigest"},
    {NDN_DTAG_ContentHash, "ContentHash"},
    {NDN_DTAG_Count, "Count"},
    {NDN_DTAG_Header, "Header"},
    {NDN_DTAG_Interest, "Interest"},
    {NDN_DTAG_Key, "Key"},
    {NDN_DTAG_KeyLocator, "KeyLocator"},
    {NDN_DTAG_KeyName, "KeyName"},
    {NDN_DTAG_Length, "Length"},
    {NDN_DTAG_Link, "Link"},
    {NDN_DTAG_LinkAuthenticator, "LinkAuthenticator"},
    {NDN_DTAG_NameComponentCount, "NameComponentCount"},
    {NDN_DTAG_ExtOpt, "ExtOpt"},
    {NDN_DTAG_RootDigest, "RootDigest"},
    {NDN_DTAG_Signature, "Signature"},
    {NDN_DTAG_Start, "Start"},
    {NDN_DTAG_Timestamp, "Timestamp"},
    {NDN_DTAG_Type, "Type"},
    {NDN_DTAG_Nonce, "Nonce"},
    {NDN_DTAG_Scope, "Scope"},
    {NDN_DTAG_Exclude, "Exclude"},
    {NDN_DTAG_Bloom, "Bloom"},
    {NDN_DTAG_BloomSeed, "BloomSeed"},
    {NDN_DTAG_AnswerOriginKind, "AnswerOriginKind"},
    {NDN_DTAG_InterestLifetime, "InterestLifetime"},
    {NDN_DTAG_Witness, "Witness"},
    {NDN_DTAG_SignatureBits, "SignatureBits"},
    {NDN_DTAG_DigestAlgorithm, "DigestAlgorithm"},
    {NDN_DTAG_BlockSize, "BlockSize"},
    {NDN_DTAG_FreshnessSeconds, "FreshnessSeconds"},
    {NDN_DTAG_FinalBlockID, "FinalBlockID"},
    {NDN_DTAG_PublisherPublicKeyDigest, "PublisherPublicKeyDigest"},
    {NDN_DTAG_PublisherCertificateDigest, "PublisherCertificateDigest"},
    {NDN_DTAG_PublisherIssuerKeyDigest, "PublisherIssuerKeyDigest"},
    {NDN_DTAG_PublisherIssuerCertificateDigest, "PublisherIssuerCertificateDigest"},
    {NDN_DTAG_ContentObject, "ContentObject"},
    {NDN_DTAG_WrappedKey, "WrappedKey"},
    {NDN_DTAG_WrappingKeyIdentifier, "WrappingKeyIdentifier"},
    {NDN_DTAG_WrapAlgorithm, "WrapAlgorithm"},
    {NDN_DTAG_KeyAlgorithm, "KeyAlgorithm"},
    {NDN_DTAG_Label, "Label"},
    {NDN_DTAG_EncryptedKey, "EncryptedKey"},
    {NDN_DTAG_EncryptedNonceKey, "EncryptedNonceKey"},
    {NDN_DTAG_WrappingKeyName, "WrappingKeyName"},
    {NDN_DTAG_Action, "Action"},
    {NDN_DTAG_FaceID, "FaceID"},
    {NDN_DTAG_IPProto, "IPProto"},
    {NDN_DTAG_Host, "Host"},
    {NDN_DTAG_Port, "Port"},
    {NDN_DTAG_MulticastInterface, "MulticastInterface"},
    {NDN_DTAG_ForwardingFlags, "ForwardingFlags"},
    {NDN_DTAG_FaceInstance, "FaceInstance"},
    {NDN_DTAG_ForwardingEntry, "ForwardingEntry"},
    {NDN_DTAG_MulticastTTL, "MulticastTTL"},
    {NDN_DTAG_MinSuffixComponents, "MinSuffixComponents"},
    {NDN_DTAG_MaxSuffixComponents, "MaxSuffixComponents"},
    {NDN_DTAG_ChildSelector, "ChildSelector"},
    {NDN_DTAG_RepositoryInfo, "RepositoryInfo"},
    {NDN_DTAG_Version, "Version"},
    {NDN_DTAG_RepositoryVersion, "RepositoryVersion"},
    {NDN_DTAG_GlobalPrefix, "GlobalPrefix"},
    {NDN_DTAG_LocalName, "LocalName"},
    {NDN_DTAG_Policy, "Policy"},
    {NDN_DTAG_Namespace, "Namespace"},
    {NDN_DTAG_GlobalPrefixName, "GlobalPrefixName"},
    {NDN_DTAG_PolicyVersion, "PolicyVersion"},
    {NDN_DTAG_KeyValueSet, "KeyValueSet"},
    {NDN_DTAG_KeyValuePair, "KeyValuePair"},
    {NDN_DTAG_IntegerValue, "IntegerValue"},
    {NDN_DTAG_DecimalValue, "DecimalValue"},
    {NDN_DTAG_StringValue, "StringValue"},
    {NDN_DTAG_BinaryValue, "BinaryValue"},
    {NDN_DTAG_NameValue, "NameValue"},
    {NDN_DTAG_Entry, "Entry"},
    {NDN_DTAG_ACL, "ACL"},
    {NDN_DTAG_ParameterizedName, "ParameterizedName"},
    {NDN_DTAG_Prefix, "Prefix"},
    {NDN_DTAG_Suffix, "Suffix"},
    {NDN_DTAG_Root, "Root"},
    {NDN_DTAG_ProfileName, "ProfileName"},
    {NDN_DTAG_Parameters, "Parameters"},
    {NDN_DTAG_InfoString, "InfoString"},
    {NDN_DTAG_StatusResponse, "StatusResponse"},
    {NDN_DTAG_StatusCode, "StatusCode"},
    {NDN_DTAG_StatusText, "StatusText"},
    {NDN_DTAG_SyncNode, "SyncNode"},
    {NDN_DTAG_SyncNodeKind, "SyncNodeKind"},
    {NDN_DTAG_SyncNodeElement, "SyncNodeElement"},
    {NDN_DTAG_SyncVersion, "SyncVersion"},
    {NDN_DTAG_SyncNodeElements, "SyncNodeElements"},
    {NDN_DTAG_SyncContentHash, "SyncContentHash"},
    {NDN_DTAG_SyncLeafCount, "SyncLeafCount"},
    {NDN_DTAG_SyncTreeDepth, "SyncTreeDepth"},
    {NDN_DTAG_SyncByteCount, "SyncByteCount"},
    {NDN_DTAG_SyncConfigSlice, "SyncConfigSlice"},
    {NDN_DTAG_SyncConfigSliceList, "SyncConfigSliceList"},
    {NDN_DTAG_SyncConfigSliceOp, "SyncConfigSliceOp"},
    {NDN_DTAG_SyncNodeDeltas, "SyncNodeDeltas"},
    {NDN_DTAG_SequenceNumber, "SequenceNumber"},
    {NDN_DTAG_NDNProtocolDataUnit, "NDNProtocolDataUnit"},
    {0, 0}
};

const struct ndn_dict ndn_dtag_dict = {ARRAY_N(ndn_tagdict) - 1, ndn_tagdict};

{-|
Module      : Crypto.LibP2P.Key
Description : Short description
Copyright   : (c) Roger Qiu, 2017
License     : MIT
Maintainer  : quoc.ho@matrix.ai
Stability   : experimental
Portability : POSIX

This module provides the Key typeclass, allowing serialization to and from
a Protobuf serialized DER format.
Compare against go-libp2p-crypto/js-libp2p-crypto.
TODO: Need to review this instance, check if the byte encodings match
-- with the implementation in go-libp2p-crypto
-}
module Crypto.LibP2P.Key where

import qualified Crypto.PubKey.Ed25519             as Ed25519
import qualified Crypto.PubKey.RSA                 as RSA
import qualified Crypto.Secp256k1                  as Secp256k1

import qualified Data.ASN1.Encoding                as ASN1Encoding
import qualified Data.ASN1.Types                   as ASN1Types
import qualified Data.ByteString                   as BSStrict
import qualified Data.ByteString.Lazy              as BSLazy
import qualified Data.X509                         as X509

import qualified Crypto.LibP2P.Protobuf.KeyType    as ProtoKeyType
import qualified Crypto.LibP2P.Protobuf.PrivateKey as ProtoPrivKey
import qualified Crypto.LibP2P.Protobuf.PublicKey  as ProtoPubKey

import           Crypto.PubKey.RSA.Types           ()
import           Data.ASN1.BinaryEncoding          (DER (..))
import           Data.ByteArray                    (convert)
import           Text.ProtocolBuffers.WireMessage  (messagePut)

class (Eq a) => Key a where
  toBytes :: a -> BSStrict.ByteString
  fromBytes :: BSStrict.ByteString -> Either String a

instance Key Ed25519.PublicKey where
  toBytes k =
    BSLazy.toStrict
    $ messagePut
    $ ProtoPubKey.PublicKey ProtoKeyType.Ed25519
    $ BSLazy.fromStrict
    $ convert k
  fromBytes = undefined

instance Key Ed25519.SecretKey where
  toBytes k =
    BSLazy.toStrict
    $ messagePut
    $ ProtoPrivKey.PrivateKey ProtoKeyType.Ed25519
    $ BSLazy.fromStrict
    $ convert k
  fromBytes = undefined

instance Key Secp256k1.PubKey where
  toBytes k =
    BSLazy.toStrict
    $ messagePut
    $ ProtoPubKey.PublicKey ProtoKeyType.Secp256k1
    $ BSLazy.fromStrict
    $ Secp256k1.exportPubKey True k
  fromBytes = undefined

instance Key Secp256k1.SecKey where
  toBytes k =
    BSLazy.toStrict
    $ messagePut
    $ ProtoPrivKey.PrivateKey ProtoKeyType.Secp256k1
    $ BSLazy.fromStrict
    $ Secp256k1.getSecKey k
  fromBytes = undefined

-- We rely on X509 and PKIX infrastructure for the serialization of
-- RSA public keys
instance Key RSA.PublicKey where
  toBytes k =
     ASN1Encoding.encodeASN1' DER
    $ (ASN1Types.toASN1 $ X509.PubKeyRSA k) []
  fromBytes = undefined

-- However, Private Keys are serialized using the form defined in
-- PKCS#1 v1.5. Since cryptonite doesn't export the serialization format
-- at the moment, we add the orphan instance in this library
instance Key RSA.PrivateKey where
  toBytes k =
    ASN1Encoding.encodeASN1' DER
    $ (ASN1Types.toASN1 k) []
  fromBytes = undefined

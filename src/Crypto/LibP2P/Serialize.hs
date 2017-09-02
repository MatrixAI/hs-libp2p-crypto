{-|
Module      : Crypto.LibP2P.Serialize
Description : protobuf serialization of cryptographic keys
License     : Apache-2.0
Maintainer  : quoc.ho@matrix.ai
Stability   : experimental
Portability : POSIX

This module provides the Serial typeclass, allowing serialization to
a Protocol Buffers format. Compare against go-libp2p-crypto/js-libp2p-crypto.

TODO: Need to review this instance, check if the byte encodings match
with the implementation in go-libp2p-crypto
-}
module Crypto.LibP2P.Serialize where

import           Crypto.LibP2P.Key

import qualified Crypto.LibP2P.Protobuf.KeyType    as ProtoKeyType
import qualified Crypto.LibP2P.Protobuf.PrivateKey as ProtoPrivKey
import qualified Crypto.LibP2P.Protobuf.PublicKey  as ProtoPubKey
import qualified Crypto.PubKey.Ed25519             as Ed25519
import qualified Crypto.PubKey.RSA                 as RSA
import qualified Crypto.Secp256k1                  as Secp256k1

import qualified Data.ASN1.Encoding                as ASN1Encoding
import qualified Data.ASN1.Types                   as ASN1Types
import qualified Data.X509                         as X509
import qualified Data.ByteString                   as BS
import qualified Data.ByteString.Lazy              as BSL

import           Data.ASN1.BinaryEncoding          (DER (..))
import           Data.ByteArray                    (convert)
import           Text.ProtocolBuffers.WireMessage  (messagePut)

-- imports ASN1Object instance for RSA.PrivateKey
import           Crypto.PubKey.RSA.Types           ()

-- TODO: We may be able to get a better implementation by deriving 
-- Generic and other typeclasses here
class (Eq a) => Serial a where
  serialize :: a -> BS.ByteString

instance Serial Ed25519.PublicKey where
  serialize k =
    encodeProtoPublic ProtoKeyType.Ed25519
    $ convert k

instance Serial Ed25519.SecretKey where
  serialize k =
    encodeProtoPrivate ProtoKeyType.Ed25519
    $ convert k

instance Serial Secp256k1.PubKey where
  serialize k =
    encodeProtoPublic ProtoKeyType.Secp256k1
    $ Secp256k1.exportPubKey True k

instance Serial Secp256k1.SecKey where
  serialize k =
    encodeProtoPrivate ProtoKeyType.Secp256k1
    $ Secp256k1.getSecKey k

-- We rely on X509 and PKIX infrastructure for the serialization of
-- RSA public keys
instance Serial RSA.PublicKey where
  serialize k =
    encodeProtoPublic ProtoKeyType.RSA
    $ ASN1Encoding.encodeASN1' DER
    $ (ASN1Types.toASN1 $ X509.PubKeyRSA k) []

-- Private Keys are serialized using the form defined in
-- PKCS#1 v1.5. Since cryptonite doesn't export the serialization format (ASN1)
-- at the moment, we add the orphan instance in Crypto.PubKey.RSA.Types
-- of this library
instance Serial RSA.PrivateKey where
  serialize k =
    encodeProtoPrivate ProtoKeyType.RSA
    $ ASN1Encoding.encodeASN1' DER
    $ (ASN1Types.toASN1 k) []

-- TODO: GHC Generics may provide the ability to derive this instance
-- automatically based on the constructors, which may give a better 
-- implementation, although it may require lifting the wrapped type
-- GADT style. For now, we derive the instance manually.
instance Serial Key where
  serialize (RSAPub k)        = serialize k
  serialize (RSAPriv k)       = serialize k
  -- serialize (Ed25519Pub k)    = serialize k
  -- serialize (Ed25519Priv k)   = serialize k
  -- serialize (Secp256k1Pub k)  = serialize k
  -- serialize (Secp256k1Priv k) = serialize k

encodeProtoPublic :: ProtoKeyType.KeyType -> BS.ByteString -> BS.ByteString
encodeProtoPublic kt bs =
  BSL.toStrict
  $ messagePut
  $ ProtoPubKey.PublicKey kt
  $ BSL.fromStrict bs

encodeProtoPrivate :: ProtoKeyType.KeyType -> BS.ByteString -> BS.ByteString
encodeProtoPrivate kt bs =
  BSL.toStrict
  $ messagePut
  $ ProtoPrivKey.PrivateKey kt
  $ BSL.fromStrict bs


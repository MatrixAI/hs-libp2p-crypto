{-|
Module      : Crypto.LibP2P.Key
Description : protobuf serialization of cryptographic keys
Copyright   : (c) Roger Qiu, 2017
License     : MIT
Maintainer  : quoc.ho@matrix.ai
Stability   : experimental
Portability : POSIX

This module provides the Key typeclass, allowing serialization to and from
a Protobuf serialized format.
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
import qualified Data.Bifunctor                    as Bifunctor
import qualified Data.ByteString                   as BSStrict
import qualified Data.ByteString.Lazy              as BSLazy
import qualified Data.X509                         as X509

import qualified Crypto.LibP2P.Protobuf.KeyType    as ProtoKeyType
import qualified Crypto.LibP2P.Protobuf.PrivateKey as ProtoPrivKey
import qualified Crypto.LibP2P.Protobuf.PublicKey  as ProtoPubKey

import           Crypto.Error                      (eitherCryptoError)
import           Data.ASN1.BinaryEncoding          (DER (..))
import           Data.ByteArray                    (convert)
import           Text.ProtocolBuffers.WireMessage  (messageGet, messagePut)

-- imports ASN1Object instance for RSA.PrivateKey
import           Crypto.PubKey.RSA.Types           ()

class (Eq a) => Key a where
  serialize :: a -> BSStrict.ByteString
  deserialize :: BSStrict.ByteString -> Either String a

instance Key Ed25519.PublicKey where
  serialize k =
    encodeProtoPublic ProtoKeyType.Ed25519
    $ convert k

  deserialize b = decodePublicKey b decodeEd25519Pub
    where
      decodeEd25519Pub :: BSStrict.ByteString -> Either String Ed25519.PublicKey
      decodeEd25519Pub bs =
        Bifunctor.first show
        $ eitherCryptoError
        $ Ed25519.publicKey bs

instance Key Ed25519.SecretKey where
  serialize k =
    encodeProtoPublic ProtoKeyType.Ed25519
    $ convert k

  deserialize b = decodePrivateKey b decodeEd25519Sec
    where
      decodeEd25519Sec :: BSStrict.ByteString -> Either String Ed25519.SecretKey
      decodeEd25519Sec bs =
        Bifunctor.first show
        $ eitherCryptoError
        $ Ed25519.secretKey bs

instance Key Secp256k1.PubKey where
  serialize k =
    encodeProtoPublic ProtoKeyType.Secp256k1
    $ Secp256k1.exportPubKey True k

  deserialize b = decodePublicKey b decodeSecp256k1Pub
    where
      decodeSecp256k1Pub :: BSStrict.ByteString -> Either String Secp256k1.PubKey
      decodeSecp256k1Pub bs =
        case Secp256k1.importPubKey bs of
             Nothing -> Left "failed to read Secp256k1.PubKey from bytestring"
             Just pk -> Right pk

instance Key Secp256k1.SecKey where
  serialize k =
    encodeProtoPublic ProtoKeyType.Secp256k1
    $ Secp256k1.getSecKey k

  deserialize b = decodePrivateKey b decodeSecp256k1Sec
    where
      decodeSecp256k1Sec :: BSStrict.ByteString -> Either String Secp256k1.SecKey
      decodeSecp256k1Sec bs =
        case Secp256k1.secKey bs of
             Nothing -> Left "failed to read Secp256k1.SecKey from bytestring"
             Just pk -> Right pk

-- We rely on X509 and PKIX infrastructure for the serialization of
-- RSA public keys
instance Key RSA.PublicKey where
  serialize k =
    encodeProtoPublic ProtoKeyType.RSA
    $ ASN1Encoding.encodeASN1' DER
    $ (ASN1Types.toASN1 $ X509.PubKeyRSA k) []

  deserialize b = decodePublicKey b decodeRSAPub
    where
      decodeRSAPub :: BSStrict.ByteString -> Either String RSA.PublicKey
      decodeRSAPub bs = derToAsn bs >>= asnToX509 >>= x509ToRSA

asnToX509 :: [ASN1Types.ASN1] -> Either String X509.PubKey
asnToX509 asn =
  Bifunctor.second fst
  $ ASN1Types.fromASN1 asn

x509ToRSA :: X509.PubKey -> Either String RSA.PublicKey
x509ToRSA (X509.PubKeyRSA k) = Right k
x509ToRSA _ = Left "Public key of x509 certificate was not of type RSA"

-- Private Keys are serialized using the form defined in
-- PKCS#1 v1.5. Since cryptonite doesn't export the serialization format (ASN1)
-- at the moment, we add the orphan instance in Crypto.PubKey.RSA.Types
-- of this library
instance Key RSA.PrivateKey where
  serialize k =
    encodeProtoPrivate ProtoKeyType.RSA
    $ ASN1Encoding.encodeASN1' DER
    $ (ASN1Types.toASN1 k) []

  deserialize b = decodePrivateKey b decodeRSAPriv
    where
      decodeRSAPriv :: BSStrict.ByteString -> Either String RSA.PrivateKey
      decodeRSAPriv bs = derToAsn bs >>= asnToRSA

      asnToRSA :: [ASN1Types.ASN1] -> Either String RSA.PrivateKey
      asnToRSA asn =
        Bifunctor.second fst
        $ ASN1Types.fromASN1 asn

derToAsn :: BSStrict.ByteString -> Either String [ASN1Types.ASN1]
derToAsn bs =
  Bifunctor.first show
  $ ASN1Encoding.decodeASN1' DER bs

encodeProtoPublic :: ProtoKeyType.KeyType ->
                     BSStrict.ByteString ->
                     BSStrict.ByteString
encodeProtoPublic kt bs =
  BSLazy.toStrict
  $ messagePut
  $ ProtoPubKey.PublicKey kt
  $ BSLazy.fromStrict bs

encodeProtoPrivate :: ProtoKeyType.KeyType ->
                      BSStrict.ByteString ->
                      BSStrict.ByteString
encodeProtoPrivate kt bs =
  BSLazy.toStrict
  $ messagePut
  $ ProtoPrivKey.PrivateKey kt
  $ BSLazy.fromStrict bs

-- TODO: decodeProto functions unwrap a protobuf key
-- and returns a bytestring representing the key as bytes.
-- There should be a better way to type this function
-- to include maybe a constructor for a given Key a
-- but this works for now until we can get a full stack working.
decodePublicKey :: (Key a) =>
                    BSStrict.ByteString ->
                   (BSStrict.ByteString -> Either String a) ->
                    Either String a
decodePublicKey bs toKey = decodeProtoPublic bs >>= toKey

decodeProtoPublic :: BSStrict.ByteString -> Either String BSStrict.ByteString
decodeProtoPublic bs =
  Bifunctor.second (BSLazy.toStrict . ProtoPubKey.data' . fst)
  $ messageGet
  $ BSLazy.fromStrict bs

decodePrivateKey :: (Key a) =>
                     BSStrict.ByteString ->
                    (BSStrict.ByteString -> Either String a) ->
                     Either String a
decodePrivateKey bs toKey = decodeProtoPrivate bs >>= toKey

decodeProtoPrivate :: BSStrict.ByteString -> Either String BSStrict.ByteString
decodeProtoPrivate bs =
  Bifunctor.second (BSLazy.toStrict . ProtoPrivKey.data' . fst)
  $ messageGet
  $ BSLazy.fromStrict bs

{-|
Module      : Crypto.LibP2P.Parse
Description : Parse protobuf serialized cryptographic keys to libp2p keys
License     : Apache-2.0
Maintainer  : quoc.ho@matrix.ai
Stability   : experimental
Portability : POSIX

TODO: Long description
-}
{-# LANGUAGE GADTs #-}
module Crypto.LibP2P.Parse where

import           Crypto.LibP2P.Key
import qualified Crypto.LibP2P.Protobuf.KeyType    as ProtoKeyType
import qualified Crypto.LibP2P.Protobuf.PrivateKey as ProtoPrivKey
import qualified Crypto.LibP2P.Protobuf.PublicKey  as ProtoPubKey


import qualified Crypto.PubKey.Ed25519             as Ed25519
import qualified Crypto.PubKey.RSA                 as RSA
import qualified Crypto.Secp256k1                  as Secp256k1
import qualified Data.Attoparsec.ByteString        as Attoparsec
import qualified Text.ProtocolBuffers.WireMessage  as PB
import qualified Data.ASN1.Encoding                as ASN1Encoding
import qualified Data.ASN1.Types                   as ASN1Types

import qualified Data.Bifunctor                    as Bifunctor
import qualified Data.ByteString                   as BS
import qualified Data.ByteString.Lazy              as BSL
import qualified Data.X509                         as X509

import           Data.ASN1.BinaryEncoding          (DER (..))
import           Crypto.Error                      (eitherCryptoError)
-- imports ASN1Object instance for RSA.PrivateKey
import           Crypto.PubKey.RSA.Types           ()

parseKey :: BS.ByteString -> Either String Key
parseKey bs = 
  Attoparsec.parseOnly keyParsers bs
  where 
    keyParsers :: Attoparsec.Parser Key
    keyParsers = 
      Attoparsec.choice 
        [ parseRSAPub
        , parseRSAPriv ]
        -- , parseEd25519Pub
        -- , parseEd25519Priv
        -- , parseSecp256k1Pub
        -- , parseSecp256k1Priv ]

eitherToParser :: Either String a -> Attoparsec.Parser a
eitherToParser a = either fail return a

parseRSAPub :: Attoparsec.Parser Key
parseRSAPub = do
  b <- Attoparsec.takeByteString
  key <- eitherToParser $ decodePublicKey b decodeRSAPub
  return $ RSAPub key
  where
    decodeRSAPub :: BS.ByteString -> Either String RSA.PublicKey
    decodeRSAPub bs = derToAsn bs >>= asnToX509 >>= x509ToRSA

parseRSAPriv :: Attoparsec.Parser Key
parseRSAPriv = do
  b <- Attoparsec.takeByteString
  key <- eitherToParser $ decodePrivateKey b decodeRSAPriv
  return $ RSAPriv key
  where
    decodeRSAPriv :: BS.ByteString -> Either String RSA.PrivateKey
    decodeRSAPriv bs = derToAsn bs >>= asnToRSA

-- parseEd25519Pub :: Attoparsec.Parser Key
-- parseEd25519Pub = do
--   b <- Attoparsec.takeByteString
--   key <- eitherToParser $ decodePublicKey b decodeEd25519Pub
--   return $ Ed25519Pub key
--   where
--     decodeEd25519Pub :: BS.ByteString -> Either String Ed25519.PublicKey
--     decodeEd25519Pub bs =
--       Bifunctor.first show
--       $ eitherCryptoError
--       $ Ed25519.publicKey bs

-- parseEd25519Priv :: Attoparsec.Parser Key
-- parseEd25519Priv = do
--   bytes <- Attoparsec.takeByteString
--   key <- eitherToParser $ decodePrivateKey bytes decodeEd25519Sec
--   return $ Ed25519Priv key
--   where
--     decodeEd25519Sec :: BS.ByteString -> Either String Ed25519.SecretKey
--     decodeEd25519Sec bs =
--       Bifunctor.first show
--       $ eitherCryptoError
--       $ Ed25519.secretKey bs

-- parseSecp256k1Pub :: Attoparsec.Parser Key
-- parseSecp256k1Pub = do
--   b <- Attoparsec.takeByteString
--   key <- eitherToParser $ decodePublicKey b decodeSecp256k1Pub
--   return $ Secp256k1Pub key
--   where
--     decodeSecp256k1Pub :: BS.ByteString -> Either String Secp256k1.PubKey
--     decodeSecp256k1Pub bs =
--       case Secp256k1.importPubKey bs of
--            Nothing -> Left "failed to read Secp256k1.PubKey from bytestring"
--            Just pk -> Right pk

-- parseSecp256k1Priv :: Attoparsec.Parser Key
-- parseSecp256k1Priv = do
--   b <- Attoparsec.takeByteString
--   key <- eitherToParser $ decodePrivateKey b decodeSecp256k1Sec
--   return $ Secp256k1Priv key
--   where
--     decodeSecp256k1Sec :: BS.ByteString -> Either String Secp256k1.SecKey
--     decodeSecp256k1Sec bs =
--       case Secp256k1.secKey bs of
--            Nothing -> Left "failed to read Secp256k1.SecKey from bytestring"
--            Just pk -> Right pk

-- TODO: decodeProto functions unwrap a protobuf key
-- and returns a bytestring representing the key as bytes.
-- There should be a better way to type this function
-- to include maybe a constructor for a given Key
-- but this works for now until we can get a full stack working.
decodePublicKey :: BS.ByteString ->
                   (BS.ByteString -> Either String a) ->
                   Either String a
decodePublicKey kb toKey = decodeProtoPublic kb >>= toKey

decodePrivateKey :: BS.ByteString ->
                    (BS.ByteString -> Either String a) ->
                    Either String a
decodePrivateKey kb toKey = decodeProtoPrivate kb >>= toKey

decodeProtoPublic :: BS.ByteString -> Either String BS.ByteString
decodeProtoPublic bs =
  Bifunctor.second (BSL.toStrict . ProtoPubKey.data' . fst)
  $ PB.messageGet
  $ BSL.fromStrict bs

decodeProtoPrivate :: BS.ByteString -> Either String BS.ByteString
decodeProtoPrivate bs =
  Bifunctor.second (BSL.toStrict . ProtoPrivKey.data' . fst)
  $ PB.messageGet
  $ BSL.fromStrict bs

-- ASN Utils
derToAsn :: BS.ByteString -> Either String [ASN1Types.ASN1]
derToAsn bs =
  Bifunctor.first show
  $ ASN1Encoding.decodeASN1' DER bs

x509ToRSA :: X509.PubKey -> Either String RSA.PublicKey
x509ToRSA (X509.PubKeyRSA k) = Right k
x509ToRSA _ = Left "Public key of x509 certificate was not of type RSA"

asnToX509 :: [ASN1Types.ASN1] -> Either String X509.PubKey
asnToX509 asn =
  Bifunctor.second fst
  $ ASN1Types.fromASN1 asn

asnToRSA :: [ASN1Types.ASN1] -> Either String RSA.PrivateKey
asnToRSA asn =
  Bifunctor.second fst
  $ ASN1Types.fromASN1 asn


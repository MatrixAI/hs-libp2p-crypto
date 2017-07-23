{-# LANGUAGE FunctionalDependencies #-}

module Crypto.LibP2P.Key where

-- this module exposes a typeclass and instances of relevant key algos for libp2p
-- the problem is that the modules exposing the various utilities are not very standardised
-- it's because there are many ways to achieve the same thing
-- like signing for RSA means getting an optional blinder, a maybe hash algorithm, the the private key and finally the bytestring which may return an error
-- however it appears the defaults have been designed into the libp2p library, so for example the sign for rsa private key in go is using a 256 checksum of the bytestring message (should we be using lazy byte strings?) then it uses SignPKCS1v15 with a random readerm a sha256 and finally the hashed array
-- so we are exposing specific ways of making use of these cryptographic algos for libp2p usage
-- also there's the usage of protobuf that we may need

import qualified Crypto.PubKey.Ed25519             as Ed25519
import qualified Crypto.PubKey.RSA                 as RSA
import qualified Crypto.Secp256k1                  as Secp256k1

import qualified Data.ASN1.Encoding                as ASN1Encoding
import qualified Data.ASN1.Types                   as ASN1Types
import qualified Data.ByteString                   as BSStrict
import qualified Data.ByteString.Base64            as Base64
import qualified Data.ByteString.Lazy              as BSLazy
import qualified Data.X509                         as X509

import qualified Crypto.LibP2P.Protobuf            as Proto
import qualified Crypto.LibP2P.Protobuf.KeyType    as ProtoKeyType
import qualified Crypto.LibP2P.Protobuf.PrivateKey as ProtoPrivKey
import qualified Crypto.LibP2P.Protobuf.PublicKey  as ProtoPubKey

import           Control.Exception.Base            (displayException)
import           Crypto.Error                      (eitherCryptoError,
                                                    maybeCryptoError,
                                                    onCryptoFailure)
import           Data.ASN1.BinaryEncoding          (BER(..), DER (..))
import           Data.ByteArray                    (convert)
import           Text.ProtocolBuffers.WireMessage  (messagePut)

class (Eq a) => Key a where
  toBytes :: a -> BSStrict.ByteString
  fromBytes :: BSStrict.ByteString -> Either String a

class (Key a, PubKey b) => PrivKey a b | a -> b where
  sign :: a -> BSStrict.ByteString -> Either String BSStrict.ByteString
  toPublic :: a -> b

class (Key a) => PubKey a where
  verify :: a -> BSStrict.ByteString -> BSStrict.ByteString -> Bool

instance Key Ed25519.PublicKey where
  toBytes k =
    BSLazy.toStrict
    $ messagePut
    $ ProtoPubKey.PublicKey ProtoKeyType.Ed25519
    $ BSLazy.fromStrict
    $ convert k
  fromBytes = undefined

-- not sure if this requires the public key and private key at the same time
-- the go returns always a 96 byte length byte string
-- need an example of a valid bytes to guide this development
instance Key Ed25519.SecretKey where
  toBytes k =
    BSLazy.toStrict
    $ messagePut
    $ ProtoPrivKey.PrivateKey ProtoKeyType.Ed25519
    $ BSLazy.fromStrict
    $ convert k
  fromBytes = undefined

instance PubKey Ed25519.PublicKey where
  verify pk bytes sigb = case eitherCryptoError $ Ed25519.signature sigb of
    Right sig -> Ed25519.verify pk bytes sig

    -- How should we handle this exception? for now, crash
    Left e  -> error $ displayException e

instance PrivKey Ed25519.SecretKey Ed25519.PublicKey where
  sign k d = Right $ convert $ Ed25519.sign k (Ed25519.toPublic k) d
  toPublic k = Ed25519.toPublic k

-- no idea if the go implementation implements DER encoding, which this does
-- the go implementation is also compressed, and we switch on compression here as well
instance Key Secp256k1.PubKey where
  toBytes k =
    BSLazy.toStrict
    $ messagePut
    $ ProtoPubKey.PublicKey ProtoKeyType.Secp256k1
    $ BSLazy.fromStrict
    $ Secp256k1.exportPubKey True k
  fromBytes = undefined

-- this is missing some sort of bitcoin serialisation scheme in the go implementation, I don't understand what that scheme is
-- the byte representation is a strict byte string containing a protobuf encoded type specified by the the proto file
instance Key Secp256k1.SecKey where
  toBytes k =
    BSLazy.toStrict
    $ messagePut
    $ ProtoPrivKey.PrivateKey ProtoKeyType.Secp256k1
    $ BSLazy.fromStrict
    $ Secp256k1.getSecKey k
  fromBytes = undefined

-- there is no ASN1 object representation of X509 keys at the moment,
-- this should be implemented, see
-- see https://github.com/vincenthz/hs-certificate/issues/55
-- https://github.com/vincenthz/hs-crypto-pubkey-types/pull/12
--
instance Key X509.PubKey where
  toBytes k =
    ASN1Encoding.encodeASN1' DER
    $ (ASN1Types.toASN1 k) []
    
  fromBytes = undefined

-- instance Key X509.PrivKey where
--   toBytes k =
--     case ASN1Encoding.encodeASN1' DER [toASN1 k] of
--       Right bs -> Base64.encode bs
--       Left e   -> show e

-- TODO: For some reason, ASN1Object instances of RSA private key are not
-- included in either the cryptonite library or x509 library.
-- This is likely because the author was trying to seperate the RSA/DSA
-- public/private keys from the serialized representation (x509/ASN1 format),
-- but in practice has led to difficulties, since any:
-- instance ASN1Object X509.PrivKey ... where
-- must case match for all value constructors of the X509.PrivKey, which in turn
-- requires instances of ASN1Object for each of those value constructors to avoid
-- introducing a partial function. Some of these values may not have
-- instance ASN1Object.
--
-- This could possibly be solved by making X509 itself a typeclass, and restricting
-- instances of the typeclass to instances of ASN1Object only.
-- See: the linked issues in the comment above.
-- For now, introduce an orphan instance of ASN1Object for RSA.PrivateKey here,
-- from the implementation in: https://git.io/v7I4b.
--
-- This should urgently be integrated into the cryptonite/x509 library, along with ASN1
-- representations of other crypto keys that depend on the certificate format,
-- as there is no way to serialize private keys that depend on x509 format without
-- significant reimplementation.
instance ASN1Types.ASN1Object RSA.PrivateKey where
    toASN1 privKey = \xs -> ASN1Types.Start ASN1Types.Sequence
                          : ASN1Types.IntVal 0
                          : ASN1Types.IntVal (RSA.public_n $ RSA.private_pub privKey)
                          : ASN1Types.IntVal (RSA.public_e $ RSA.private_pub privKey)
                          : ASN1Types.IntVal (RSA.private_d privKey)
                          : ASN1Types.IntVal (RSA.private_p privKey)
                          : ASN1Types.IntVal (RSA.private_q privKey)
                          : ASN1Types.IntVal (RSA.private_dP privKey)
                          : ASN1Types.IntVal (RSA.private_dQ privKey)
                          : ASN1Types.IntVal (fromIntegral $ RSA.private_qinv privKey)
                          : ASN1Types.End ASN1Types.Sequence
                          : xs
    fromASN1 (ASN1Types.Start ASN1Types.Sequence
             : ASN1Types.IntVal 0
             : ASN1Types.IntVal n
             : ASN1Types.IntVal e
             : ASN1Types.IntVal d
             : ASN1Types.IntVal p1
             : ASN1Types.IntVal p2
             : ASN1Types.IntVal pexp1
             : ASN1Types.IntVal pexp2
             : ASN1Types.IntVal pcoef
             : ASN1Types.End ASN1Types.Sequence
             : xs) = Right (privKey, xs)
        where calculate_modulus n i = if (2 ^ (i * 8)) > n then i else calculate_modulus n (i+1)
              privKey = RSA.PrivateKey
                        { RSA.private_pub  = RSA.PublicKey { RSA.public_size = calculate_modulus n 1
                                                   , RSA.public_n    = n
                                                   , RSA.public_e    = e
                                                   }
                        , RSA.private_d    = d
                        , RSA.private_p    = p1
                        , RSA.private_q    = p2
                        , RSA.private_dP   = pexp1
                        , RSA.private_dQ   = pexp2
                        , RSA.private_qinv = pcoef
                        }

    fromASN1 ( ASN1Types.Start ASN1Types.Sequence
             : ASN1Types.IntVal 0
             : ASN1Types.Start ASN1Types.Sequence
             : ASN1Types.OID [1, 2, 840, 113549, 1, 1, 1]
             : ASN1Types.Null
             : ASN1Types.End ASN1Types.Sequence
             : ASN1Types.OctetString bs
             : xs
             ) = let inner = either strError ASN1Types.fromASN1 $ ASN1Encoding.decodeASN1' BER bs
                     strError = Left .
                                ("fromASN1: RSA.PrivateKey: " ++) . show
                 in either Left (\(k, _) -> Right (k, xs)) inner
    fromASN1 _ =
        Left "fromASN1: RSA.PrivateKey: unexpected format"


instance Key RSA.PublicKey where
  toBytes k =
    toBytes
    $ X509.PubKeyRSA k
  fromBytes = undefined

instance Key RSA.PrivateKey where
  toBytes k =
    ASN1Encoding.encodeASN1' DER
    $ (ASN1Types.toASN1 k) []
  fromBytes = undefined

-- TODO: Instead of using a typeclass, we can use data constructors to wrap
-- the underlying key types as documented below.
-- Not sure which is the better design in this case?
--
-- data Key = PubKey PubKey | PrivKey PrivKey
--   deriving (Eq)

-- data PubKey = PubRSA RSA.PublicKey
--            | PubEd25519 Ed25519.PublicKey
--            | PubSecp256k1 Secp256k1.PubKey
--             deriving (Eq)

-- data PrivKey = PrivRSA RSA.PrivateKey
--             | PrivEd25519 Ed25519.SecretKey
--             | PrivSecp256k1 Secp256k1.SecKey
--             deriving (Eq)

-- toPublic :: PrivKey -> PubKey
-- toPublic (PrivRSA privKey) = PubRSA $ RSA.private_pub privKey
-- toPublic (PrivEd25519 privKey) = PubEd25519 $ Ed25519.toPublic privKey
-- toPublic (PrivSecp256k1 privKey) = PubSecp256k1 $ Secp256k1.derivePubKey privKey

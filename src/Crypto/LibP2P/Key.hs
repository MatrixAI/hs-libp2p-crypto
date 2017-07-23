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
--import qualified Data.ByteString.Base64            as Base64
import qualified Data.ByteString.Lazy              as BSLazy
import qualified Data.X509                         as X509

import qualified Crypto.LibP2P.Protobuf.KeyType    as ProtoKeyType
import qualified Crypto.LibP2P.Protobuf.PrivateKey as ProtoPrivKey
import qualified Crypto.LibP2P.Protobuf.PublicKey  as ProtoPubKey

import           Crypto.PubKey.RSA.Types           ()
import           Data.ASN1.BinaryEncoding          (BER(..), DER (..))
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
instance Key X509.PubKey where
  toBytes k =
    ASN1Encoding.encodeASN1' DER
    $ (ASN1Types.toASN1 k) []
    
  fromBytes = undefined

-- there is no ASN1 object representation of X509 keys at the moment,
-- this should be implemented, see
-- see https://github.com/vincenthz/hs-certificate/issues/55
-- https://github.com/vincenthz/hs-crypto-pubkey-types/pull/12
--
-- instance Key X509.PrivKey where
--   toBytes k =
--     case ASN1Encoding.encodeASN1' DER [toASN1 k] of
--       Right bs -> Base64.encode bs
--       Left e   -> show e

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

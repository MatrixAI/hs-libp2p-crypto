module Crypto.LibP2P.Key
  (
  ) where

-- this module exposes a typeclass and instances of relevant key algos for libp2p
-- the problem is that the modules exposing the various utilities are not very standardised
-- it's because there are many ways to achieve the same thing
-- like signing for RSA means getting an optional blinder, a maybe hash algorithm, the the private key and finally the bytestring which may return an error
-- however it appears the defaults have been designed into the libp2p library, so for example the sign for rsa private key in go is using a 256 checksum of the bytestring message (should we be using lazy byte strings?) then it uses SignPKCS1v15 with a random readerm a sha256 and finally the hashed array
-- so we are exposing specific ways of making use of these cryptographic algos for libp2p usage
-- also there's the usage of protobuf that we may need

import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.Secp256k1 as Secp256k1

import qualified Data.ByteString as BSStrict
import qualified Data.ByteString.Lazy as BSLazy

import qualified Crypto.LibP2P.Protobuf as Proto
import qualified Crypto.LibP2P.Protobuf.KeyType as ProtoKeyType
import qualified Crypto.LibP2P.Protobuf.PublicKey as ProtoPubKey
import qualified Crypto.LibP2P.Protobuf.PrivateKey as ProtoPrivKey

import Crypto.Error (onCryptoFailure, eitherCryptoError, maybeCryptoError)
import Text.ProtocolBuffers.WireMessage (messagePut)
import Data.ByteArray (convert)

class (Eq a) => Key a where
  toBytes :: a -> BSStrict.ByteString

class (Key a) => PrivKey a where
  sign :: a -> BSStrict.ByteString -> Either String BSStrict.ByteString
  toPublic :: (PubKey b) => a -> b

class (Key a) => PubKey a where
  verify :: a -> BSStrict.ByteString -> BSStrict.ByteString -> Bool

instance Key Ed25519.PublicKey where
  toBytes k =
    BSLazy.toStrict
    $ messagePut
    $ ProtoPubKey.PublicKey ProtoKeyType.Ed25519
    $ BSLazy.fromStrict
    $ convert k

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

instance PrivKey Ed25519.SecretKey where
  sign k d = Right $ convert $ Ed25519.sign k (Ed25519.toPublic k) d
  toPublic k = Ed25519.toPublic k

instance PubKey Ed25519.PublicKey where
  verify k d s = Ed25519.verify k d (Ed25519.signature s)

-- no idea if the go implementation implements DER encoding, which this does
-- the go implementation is also compressed, and we switch on compression here as well
instance Key Secp256k1.PubKey where
  toBytes k =
    BSLazy.toStrict
    $ messagePut
    $ ProtoPubKey.PublicKey ProtoKeyType.Secp256k1
    $ BSLazy.fromStrict
    $ Secp256k1.exportPubKey True k

-- this is missing some sort of bitcoin serialisation scheme in the go implementation, I don't understand what that scheme is
-- the byte representation is a strict byte string containing a protobuf encoded type specified by the the proto file
instance Key Secp256k1.SecKey where
  toBytes k =
    BSLazy.toStrict
    $ messagePut
    $ ProtoPrivKey.PrivateKey ProtoKeyType.Secp256k1
    $ BSLazy.fromStrict
    $ Secp256k1.getSecKey k


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

-- toBytes :: Key -> BSStrict.ByteString

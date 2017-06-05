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

class (Eq a) => Key a where
  toBytes :: a -> BSStrict.ByteString

-- wait a minute, toPublic just says that a private key can be turned into a pubkey
class (Key a) => PrivKey a where
  sign :: a -> BSStrict.ByteString -> Either String BSStrict.ByteString
  toPublic :: (PubKey b) => a -> b

class (Key a) => PubKey a where
  verify :: a -> BSStrict.ByteString -> BSStrict.ByteString -> Bool

-- this all uses protobuf!!!
-- the go version does this
-- it takes the keys, and allocates new space using pb.PrivateKey type
-- this is a struct containing a Type :: *KeyType, Data :: []byte, ...
-- it assigns thetype to a &typ, which is the key type integer, it is like 0,1,2 kind of thing
-- Data is assigned to btcec (bitcoin encoded) of the key and serialized into bytestring
-- the whole thing is marshalled into the protobuf wire format
-- I don't understand how the protobuf marshalling function works with regards to the types and the message
-- I needto use the same proto file and compile a haskell version of it

-- instance Key Secp256k1.PubKey where
--   toBytes = Secp256k1.exportPubKey

instance Key Secp256k1.SecKey where
  toBytes = Secp256k1.getSecKey


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

{-# LANGUAGE FunctionalDependencies #-}

{-|
Module      : Crypto.LibP2P.PrivKey
Description : Short description
Copyright   : (c) Roger Qiu, 2017
License     : MIT
Maintainer  : roger.qiu@matrix.ai
Stability   : experimental
Portability : POSIX

Here is a longer description of this module, containing some
commentary with @some markup@.
-}
module Crypto.LibP2P.PrivKey where

import           Crypto.LibP2P.Key
import           Crypto.LibP2P.PubKey

import qualified Crypto.Hash.Algorithms   as Hash
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA        as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import qualified Crypto.Secp256k1         as Secp256k1
import qualified Data.ByteString          as BS

import           Data.ByteArray           (convert)

class (Key a, PubKey b) => PrivKey a b | a -> b where
  sign :: a -> BS.ByteString -> Either String BS.ByteString
  toPublic :: a -> b

instance PrivKey Ed25519.SecretKey Ed25519.PublicKey where
  sign k d = Right $ convert $ Ed25519.sign k (Ed25519.toPublic k) d
  toPublic k = Ed25519.toPublic k

instance PrivKey Secp256k1.SecKey Secp256k1.PubKey where
  sign k d = case Secp256k1.msg d of
                  Nothing ->
                    Left "Failed parsing bytes to Secp256k1.Msg"
                  Just m ->
                    Right $ Secp256k1.exportSig $ Secp256k1.signMsg k m
  toPublic k = Secp256k1.derivePubKey k

-- TODO: Adding a blinder to this computation requires
-- the introduction of MonadRandom, which means the
-- type signature of sign will have to be changed.
-- For now, we omit the blinder, but this should be added
-- once we figure out the best type signature for this typeclass
instance PrivKey RSA.PrivateKey RSA.PublicKey where
  sign k d = case PKCS15.sign Nothing (Just Hash.SHA256) k d of
                  Left e    -> Left $ show e
                  Right sig -> Right sig
  toPublic k = RSA.private_pub k

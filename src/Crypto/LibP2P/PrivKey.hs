{-# LANGUAGE FunctionalDependencies #-}

{-|
Module      : Crypto.LibP2P.PrivKey
Description : Short description
Copyright   : (c) Roger Qiu, 2017
License     : MIT
Maintainer  : quoc-an.ho@matrix.ai
Stability   : experimental
Portability : POSIX

Here is a longer description of this module, containing some
commentary with @some markup@.
-}
module Crypto.LibP2P.PrivKey where

import Crypto.LibP2P.Key
import Crypto.LibP2P.PubKey

import qualified Crypto.PubKey.Ed25519             as Ed25519
import qualified Crypto.PubKey.RSA                 as RSA
import qualified Crypto.Secp256k1                  as Secp256k1

import qualified Data.ByteString                   as BSStrict
import qualified Data.X509                         as X509

import           Data.ByteArray                    (convert)
import           Text.ProtocolBuffers.WireMessage  (messagePut)

class (Key a, PubKey b) => PrivKey a b | a -> b where
  sign :: a -> BSStrict.ByteString -> Either String BSStrict.ByteString
  toPublic :: a -> b

instance PrivKey Ed25519.SecretKey Ed25519.PublicKey where
  sign k d = Right $ convert $ Ed25519.sign k (Ed25519.toPublic k) d
  toPublic k = Ed25519.toPublic k

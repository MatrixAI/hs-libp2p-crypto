{-|
Module      : Crypto.LibP2P.Key
Description : Short description
Copyright   : (c) Roger Qiu, 2017
License     : MIT
Maintainer  : quoc.ho@matrix.ai
Stability   : experimental
Portability : POSIX

Here is a longer description of this module, containing some
commentary with @some markup@.
-}
module Crypto.LibP2P.PubKey where

import           Crypto.LibP2P.Key

import qualified Crypto.Hash.Algorithms           as Hash
import qualified Crypto.PubKey.Ed25519            as Ed25519
import qualified Crypto.PubKey.RSA                as RSA
import qualified Crypto.PubKey.RSA.PKCS15         as RSAPKCS15
import qualified Crypto.Secp256k1                 as Secp256k1
import qualified Data.ByteString                  as BS

import           Control.Exception.Base           (displayException)
import           Crypto.Error                     (eitherCryptoError)
import           Data.ByteArray                   (convert)
import           Text.ProtocolBuffers.WireMessage (messagePut)

class (Key a) => PubKey a where
  -- verify takes a key, message as bytes, and signature as bytes,
  -- and returns True if the signature matches the message
  verify :: a -> BS.ByteString -> BS.ByteString -> Either String Bool

instance PubKey Ed25519.PublicKey where
  verify pk msgb sigb = case eitherCryptoError $ Ed25519.signature sigb of
                             Right sig -> Right $ Ed25519.verify pk msgb sig

                             -- TODO: if we fail to parse the signature, return
                             -- an Either CryptoError Bool to that effect.
                             Left e    -> Left $ show e

instance PubKey Secp256k1.PubKey where
  verify pk msgb sigb =
    let mSig = Secp256k1.importSig sigb
        mMsg = Secp256k1.msg msgb
    in case mSig of
            Nothing -> Right False
            Just sig -> case mMsg of
                             Nothing  ->
                               Left $ "Failed to parse Secp256k1 message"
                             Just msg -> Right $ Secp256k1.verifySig pk sig msg

instance PubKey RSA.PublicKey where
  verify pk msgb sigb = Right $ RSAPKCS15.verify (Just Hash.SHA256) pk msgb sigb

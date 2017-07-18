{-# LANGUAGE DataKinds #-}

import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.Secp256k1 as Secp256k1
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS


import Crypto.Error (CryptoFailable(..))
import Crypto.LibP2P.Key
import Control.Monad
import Data.Word
import Data.Serialize.Put
import Test.QuickCheck
import Test.QuickCheck.Gen

instance Arbitrary Ed25519.PublicKey where
  arbitrary = do 
    words <- replicateM 4 $ choose (minBound, maxBound)
    let (_, rb) = runPutM $ mapM putWord64be words 
    case Ed25519.publicKey rb of
      CryptoFailed e -> error $ show e ++ (show rb)
      CryptoPassed pk -> return pk

-- Phantom type used to pass instance type info to the compiler
data (Key a) => KeyT a = KeyT

instance Arbitrary Ed25519.SecretKey where
  arbitrary = do 
    words <- replicateM 4 $ choose (minBound, maxBound)
    let (_, rb) = runPutM $ mapM putWord64be words 
    case Ed25519.secretKey rb of
      CryptoFailed e -> error $ show e ++ (show rb)
      CryptoPassed sk -> return sk

instance Arbitrary RSA.PublicKey where
  arbitrary = do
    size <- elements [16,32,64,128,256,512,1024,2048,4096,8192]
    -- these should be randomly chosen?
    -- later versions of QuickCheck add chooseAny, but
    -- we are currently restricted by the resolver we are running
    -- use arbitrary for now
    n <- arbitrary
    e <- arbitrary
    return $ RSA.PublicKey size n e

genEd25519PubKey :: Gen Ed25519.PublicKey
genEd25519PubKey = arbitrary

genEd25519PrivKey :: Gen Ed25519.PublicKey
genEd25519PrivKey = arbitrary

genSecp256k1PubKey :: Gen Secp256k1.PubKey
genSecp256k1PubKey = arbitrary

genRSAPubKey :: Gen RSA.PublicKey
genRSAPubKey = arbitrary

-- Not all PrivKey types are showable, so Blind is used to wrap them
-- as QuickCheck requires showable input parameters
-- KeyT is used to have the compiler infer the PrivKey instance when it is called
prop_TestSignAndVerify :: (PrivKey a b, Arbitrary a) => KeyT a -> Blind a -> [Word8] -> Bool
prop_TestSignAndVerify _ sk bytes = verify (toPublic $ getBlind sk) (BS.pack bytes) sig
                               where
                                  sig = case sign (getBlind sk) (BS.pack bytes) of
                                          Right bs -> bs
                                          Left e -> error e

--prop_TestEncode :: (Key a, PrivKey a b) => KeyT a -> Blind a -> Bool
--prop_TestEncode _ sk = (getBlind sk) == fromBytes $ toBytes $ (getBlind sk)

main :: IO ()
main = do
  quickCheck . verbose $ prop_TestSignAndVerify (KeyT :: KeyT Ed25519.SecretKey)
  -- sample genEd25519PubKey
  -- sample genSecp256k1PubKey
  -- sample genRSAPubKey

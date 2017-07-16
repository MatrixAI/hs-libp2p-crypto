
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.Secp256k1 as Secp256k1
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS

import Crypto.Error (CryptoFailable(..))
import Control.Monad
import Data.Word
import Data.Serialize.Put
import Test.QuickCheck
import Test.QuickCheck.Gen

instance Arbitrary Ed25519.PublicKey where
  arbitrary = do 
    words <- replicateM 4 $ choose (minBound, maxBound)
    let (_, rb) = runPutM $ mapM putWord64le words 
    case Ed25519.publicKey rb of
      CryptoFailed e -> error $ show e ++ (show rb)
      CryptoPassed pk -> return pk

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

genSecp256k1PubKey :: Gen Secp256k1.PubKey
genSecp256k1PubKey = arbitrary

genRSAPubKey :: Gen RSA.PublicKey
genRSAPubKey = arbitrary

main :: IO ()
main = do
  sample genEd25519PubKey
  sample genSecp256k1PubKey
  sample genRSAPubKey


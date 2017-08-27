module Crypto.LibP2P.Key where

import qualified Crypto.PubKey.Ed25519             as Ed25519
import qualified Crypto.PubKey.RSA                 as RSA
import qualified Crypto.Secp256k1                  as Secp256k1

-- TODO: Parsing is ambiguous for Ed25519 keys
-- Also issues with Secp256k1 keys that need to be debugged
-- For now, only use RSA as the keytype, and figure out 
-- what to do about ambiguous parsing later
data Key
  = RSAPub        RSA.PublicKey
  | RSAPriv       RSA.PrivateKey
  -- | Ed25519Pub    Ed25519.PublicKey
  -- | Ed25519Priv   Ed25519.SecretKey
  -- | Secp256k1Pub  Secp256k1.PubKey
  -- | Secp256k1Priv Secp256k1.SecKey
  deriving (Show, Eq)

makeRSAPubKey :: RSA.PublicKey -> Key
makeRSAPubKey k = RSAPub k

makeRSAPrivKey :: RSA.PrivateKey -> Key
makeRSAPrivKey k = RSAPriv k

-- makeEd25519PubKey :: Ed25519.PublicKey -> Key
-- makeEd25519PubKey k = Ed25519Pub k

-- makeEd25519PrivKey :: Ed25519.SecretKey -> Key
-- makeEd25519PrivKey k = Ed25519Priv k

-- makeSecp256k1PubKey :: Secp256k1.PubKey -> Key
-- makeSecp256k1PubKey k = Secp256k1Pub k

-- makeSecp256k1PrivKey  :: Secp256k1.SecKey -> Key
-- makeSecp256k1PrivKey k = Secp256k1Priv k

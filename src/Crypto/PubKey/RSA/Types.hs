module Crypto.PubKey.RSA.Types where

import qualified Crypto.PubKey.RSA  as RSA

import qualified Data.ASN1.Encoding as ASN1Encoding
import qualified Data.ASN1.Types    as ASN1Types

import           Data.ASN1.BinaryEncoding   (BER(..), DER(..))

-- TODO: For some reason, ASN1Object instances of RSA private key are not
-- included in cryptonite library for Crypto.PubKey.RSA.PKCS15. 
-- This is likely because the author was trying to seperate the RSA/DSA
-- public/private keys from the serialized representation defined by PKCS#1.
-- Unfortunately, we are now left with no way to serialize RSA private keys.
--
-- For now, introduce an orphan instance of ASN1Object for RSA.PrivateKey here,
-- from the implementation in: https://git.io/v7I4b.
--
-- This should be integrated into the cryptonite or crypto-storage library, along with ASN1
-- representations for other private keys.
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

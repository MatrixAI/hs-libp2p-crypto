{-# LANGUAGE BangPatterns, DeriveDataTypeable, FlexibleInstances, MultiParamTypeClasses #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}
module Crypto.LibP2P.Protobuf.PublicKey (PublicKey(..)) where
import Prelude ((+), (/))
import qualified Prelude as Prelude'
import qualified Data.Typeable as Prelude'
import qualified Data.Data as Prelude'
import qualified Text.ProtocolBuffers.Header as P'
import qualified Crypto.LibP2P.Protobuf.KeyType as Crypto.LibP2P.Protobuf (KeyType)
 
data PublicKey = PublicKey{type' :: !(Crypto.LibP2P.Protobuf.KeyType), data' :: !(P'.ByteString)}
               deriving (Prelude'.Show, Prelude'.Eq, Prelude'.Ord, Prelude'.Typeable, Prelude'.Data)
 
instance P'.Mergeable PublicKey where
  mergeAppend (PublicKey x'1 x'2) (PublicKey y'1 y'2) = PublicKey (P'.mergeAppend x'1 y'1) (P'.mergeAppend x'2 y'2)
 
instance P'.Default PublicKey where
  defaultValue = PublicKey P'.defaultValue P'.defaultValue
 
instance P'.Wire PublicKey where
  wireSize ft' self'@(PublicKey x'1 x'2)
   = case ft' of
       10 -> calc'Size
       11 -> P'.prependMessageSize calc'Size
       _ -> P'.wireSizeErr ft' self'
    where
        calc'Size = (P'.wireSizeReq 1 14 x'1 + P'.wireSizeReq 1 12 x'2)
  wirePut ft' self'@(PublicKey x'1 x'2)
   = case ft' of
       10 -> put'Fields
       11 -> do
               P'.putSize (P'.wireSize 10 self')
               put'Fields
       _ -> P'.wirePutErr ft' self'
    where
        put'Fields
         = do
             P'.wirePutReq 8 14 x'1
             P'.wirePutReq 18 12 x'2
  wireGet ft'
   = case ft' of
       10 -> P'.getBareMessageWith update'Self
       11 -> P'.getMessageWith update'Self
       _ -> P'.wireGetErr ft'
    where
        update'Self wire'Tag old'Self
         = case wire'Tag of
             8 -> Prelude'.fmap (\ !new'Field -> old'Self{type' = new'Field}) (P'.wireGet 14)
             18 -> Prelude'.fmap (\ !new'Field -> old'Self{data' = new'Field}) (P'.wireGet 12)
             _ -> let (field'Number, wire'Type) = P'.splitWireTag wire'Tag in P'.unknown field'Number wire'Type old'Self
 
instance P'.MessageAPI msg' (msg' -> PublicKey) PublicKey where
  getVal m' f' = f' m'
 
instance P'.GPB PublicKey
 
instance P'.ReflectDescriptor PublicKey where
  getMessageInfo _ = P'.GetMessageInfo (P'.fromDistinctAscList [8, 18]) (P'.fromDistinctAscList [8, 18])
  reflectDescriptorInfo _
   = Prelude'.read
      "DescriptorInfo {descName = ProtoName {protobufName = FIName \".Crypto.LibP2P.Protobuf.PublicKey\", haskellPrefix = [], parentModule = [MName \"Crypto\",MName \"LibP2P\",MName \"Protobuf\"], baseName = MName \"PublicKey\"}, descFilePath = [\"Crypto\",\"LibP2P\",\"Protobuf\",\"PublicKey.hs\"], isGroup = False, fields = fromList [FieldInfo {fieldName = ProtoFName {protobufName' = FIName \".Crypto.LibP2P.Protobuf.PublicKey.Type\", haskellPrefix' = [], parentModule' = [MName \"Crypto\",MName \"LibP2P\",MName \"Protobuf\",MName \"PublicKey\"], baseName' = FName \"type'\", baseNamePrefix' = \"\"}, fieldNumber = FieldId {getFieldId = 1}, wireTag = WireTag {getWireTag = 8}, packedTag = Nothing, wireTagLength = 1, isPacked = False, isRequired = True, canRepeat = False, mightPack = False, typeCode = FieldType {getFieldType = 14}, typeName = Just (ProtoName {protobufName = FIName \".Crypto.LibP2P.Protobuf.KeyType\", haskellPrefix = [], parentModule = [MName \"Crypto\",MName \"LibP2P\",MName \"Protobuf\"], baseName = MName \"KeyType\"}), hsRawDefault = Nothing, hsDefault = Nothing},FieldInfo {fieldName = ProtoFName {protobufName' = FIName \".Crypto.LibP2P.Protobuf.PublicKey.Data\", haskellPrefix' = [], parentModule' = [MName \"Crypto\",MName \"LibP2P\",MName \"Protobuf\",MName \"PublicKey\"], baseName' = FName \"data'\", baseNamePrefix' = \"\"}, fieldNumber = FieldId {getFieldId = 2}, wireTag = WireTag {getWireTag = 18}, packedTag = Nothing, wireTagLength = 1, isPacked = False, isRequired = True, canRepeat = False, mightPack = False, typeCode = FieldType {getFieldType = 12}, typeName = Nothing, hsRawDefault = Nothing, hsDefault = Nothing}], keys = fromList [], extRanges = [], knownKeys = fromList [], storeUnknown = False, lazyFields = False, makeLenses = False}"
 
instance P'.TextType PublicKey where
  tellT = P'.tellSubMessage
  getT = P'.getSubMessage
 
instance P'.TextMsg PublicKey where
  textPut msg
   = do
       P'.tellT "Type" (type' msg)
       P'.tellT "Data" (data' msg)
  textGet
   = do
       mods <- P'.sepEndBy (P'.choice [parse'type', parse'data']) P'.spaces
       Prelude'.return (Prelude'.foldl (\ v f -> f v) P'.defaultValue mods)
    where
        parse'type'
         = P'.try
            (do
               v <- P'.getT "Type"
               Prelude'.return (\ o -> o{type' = v}))
        parse'data'
         = P'.try
            (do
               v <- P'.getT "Data"
               Prelude'.return (\ o -> o{data' = v}))
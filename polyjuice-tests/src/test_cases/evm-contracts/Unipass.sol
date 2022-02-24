// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Unipass {
    enum KeyType{RSA, Secp256K1, Secp256R1}
    // RSA的key为 2048 bit位二进制串。key.length = 256;
    // Secp256K1的key为以太坊地址。 key.length = 20;
    // Secp256R1的key为64 bytes。 key.length = 64;
    struct PubKey {
        uint keyType;
        bytes key;
    }

     // 用户基本信息
    struct UserInfo {
        bytes32 registerEmail;          // 注册邮箱的sha256_hash
        uint nonce;						// 用户的操作nonce，用来防止replay attack
        PubKey[] keys;					// 用户已经生效的公钥
    }

    enum ActionType {
        REGISTER,
        ADD_LOCAL_KEY,
        DEL_LOCAL_KEY
    }

    //event
    //event event_dbg(bytes32 msg);
    event event_register(bytes32, string);
    event event_addLocalKey(bytes32, uint, bytes);
    event event_delLocalKey(bytes32, uint, bytes);

    mapping(bytes32 => UserInfo) public users;		// 所有用户
    uint public totalUsers;							// 用户总数
    PubKey public admin;                            // 管理员
    uint8 public chainID;                           // chainID = 0测试网 chainID = 1 正式网网


    function _register(
            bytes32 registerEmail,
            uint keyType,
            bytes memory key
        ) private {
    
        users[registerEmail].registerEmail = registerEmail;
        users[registerEmail].nonce = 1;
        PubKey memory k = PubKey(keyType, key);
        users[registerEmail].keys.push(k);
    }

    // 通过邮件来完成用户注册
    function register(
        bytes32 registerEmail,					// 注册邮箱地址的sha256 hash
        uint keyType,							// key类型
        bytes memory key,						// key数据
        string memory source                    // 用户来源
    ) public {
        //check parameters
        require(users[registerEmail].registerEmail == bytes32(0), "register email has been registered");
        require(keyType <= uint(KeyType.Secp256R1)              , "register keyType err");
        require(key.length > 0                                  , "register key err");
        require(bytes(source).length > 0                        , "register source err");

        // 2. 新建一条UserInfo记录
        _register(registerEmail, keyType, key);

        totalUsers = totalUsers + 1;

        //event
        emit event_register(registerEmail, source);
    }


    function _addkey(bytes32 registerEmail, uint newkeyType, bytes memory newKey) private {
        bool empty = false;
        for(uint i=0 ; i < users[registerEmail].keys.length ; i++){
            if(users[registerEmail].keys[i].key.length == 0){
                users[registerEmail].keys[i].keyType = newkeyType;
                users[registerEmail].keys[i].key = newKey;
                empty = true;
                break;
            }
        }
        if(empty == false){
            PubKey memory pk = PubKey(newkeyType, newKey);
            users[registerEmail].keys.push(pk);
        }
    }

    // 用合约中已经生效的key对新key进行签名，完成添加新key
    function addLocalKey(
        bytes32 registerEmail,
        uint nonce,
        uint newkeyType,
        bytes memory newKey
    ) public {
        //check parameters
        require(users[registerEmail].registerEmail != bytes32(0), "addLocalKey user is not exist");
        require(newkeyType <= uint(KeyType.Secp256R1)           , "addLocalKey newkeyType err");
        require(newKey.length > 0                               , "addLocalKey newKey err");

        // 1. check nonce 
        require(users[registerEmail].nonce+1 == nonce, "addLocalKey nonce invalid"); 

        //- 更新数据
        _addkey(registerEmail, newkeyType, newKey);
        users[registerEmail].nonce++;

        //event
        emit event_addLocalKey(registerEmail, newkeyType, newKey);
    }

    // 用合约中已经生效的key，对生效的待删除key进行签名，完成key的删除
    function delLocalKey(
        bytes32 registerEmail,
        uint nonce,
        uint delKeyType,			    // 待删除key的类型
        bytes memory delKey				// 待删除key							
    ) public{
        //check parameters
        require(users[registerEmail].registerEmail != bytes32(0), "delLocalKey user is not exist");
        require(delKeyType <= uint(KeyType.Secp256R1)           , "delLocalKey delKeyType err");
        require(delKey.length > 0                               , "delLocalKey delKey err");

        // 1. check user exist & user.nonce == nonce
        require(users[registerEmail].nonce+1 == nonce           ,'delLocalKey nonce error');

        // 2. check sigKey exist
        // 3. check delKey exist 
        bool delKeyexist = false;
        uint delindex = 0;
        for(uint i=0; i<users[registerEmail].keys.length; i++){
            if(users[registerEmail].keys[i].keyType == delKeyType && keccak256(users[registerEmail].keys[i].key) == keccak256(delKey)){
                delKeyexist = true;
                delindex = i;
            }
        }
        require(delKeyexist == true,'delLocalKey sigKey or delKey not exist');

        //- 更新数据
        delete users[registerEmail].keys[delindex];
        users[registerEmail].nonce++;

        //event
        emit event_delLocalKey(registerEmail,delKeyType,delKey);
    }


    function getLocalKey(
        bytes32 registerEmail,
        uint index
        )
        public
        view
        returns (uint256, bytes memory)
    {
        require(users[registerEmail].keys.length > index, "no such key");
        require(users[registerEmail].keys[index].key.length > 0);
        return (users[registerEmail].keys[index].keyType, users[registerEmail].keys[index].key);
    }
}
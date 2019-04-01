var APIResult, Blacklist, Cache, Config, DataVersion, Friendship, Group, GroupMember, GroupSync, LoginLog, MAX_GROUP_MEMBER_COUNT, NICKNAME_MAX_LENGTH, NICKNAME_MIN_LENGTH, PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH, PORTRAIT_URI_MAX_LENGTH, PORTRAIT_URI_MIN_LENGTH, Session, User, Reports, Utility, VerificationCode, _, co, express, getToken, moment, qiniu, fs, ref, regionMap, rongCloud, router, sequelize, validator;

express = require('express');

co = require('co');

_ = require('underscore');

moment = require('moment');

rongCloud = require('rongcloud-sdk');

qiniu = require('qiniu');

fs = require('fs');

Config = require('../conf');

Cache = require('../util/cache');

Session = require('../util/session');

Utility = require('../util/util').Utility;

APIResult = require('../util/util').APIResult;

ref = require('../db'), sequelize = ref[0], User = ref[1], Blacklist = ref[2], Friendship = ref[3], Group = ref[4], GroupMember = ref[5], GroupSync = ref[6], DataVersion = ref[7], VerificationCode = ref[8], LoginLog = ref[9], Reports = ref[10];

MAX_GROUP_MEMBER_COUNT = 500;

NICKNAME_MIN_LENGTH = 1;

NICKNAME_MAX_LENGTH = 32;

PORTRAIT_URI_MIN_LENGTH = 12;

PORTRAIT_URI_MAX_LENGTH = 256;

PASSWORD_MIN_LENGTH = 6;

PASSWORD_MAX_LENGTH = 20;

rongCloud.init(Config.RONGCLOUD_APP_KEY, Config.RONGCLOUD_APP_SECRET);

router = express.Router();

validator = sequelize.Validator;

regionMap = {
  '86': 'zh-CN'
};

getToken = function(userId, nickname, portraitUri) {
  return new Promise(function(resolve, reject) {
    return rongCloud.user.getToken(Utility.encodeId(userId), nickname, portraitUri, function(err, resultText) {
      var result;
      if (err) {
        return reject(err);
      }
      result = JSON.parse(resultText);
      if (result.code !== 200) {
        return reject(new Error('RongCloud Server API Error Code: ' + result.code));
      }
      return User.update({
        rongCloudToken: result.token
      }, {
        where: {
          id: userId
        }
      }).then(function() {
        return resolve(result.token);
      })["catch"](function(error) {
        return reject(error);
      });
    });
  });
};

router.post('/send_code', function(req, res, next) {
  var phone, region;
  region = req.body.region;
  phone = req.body.phone;
  if (!validator.isMobilePhone(phone.toString(), regionMap[region])) {
    return res.status(400).send('Invalid region and phone number.');
  }
  return VerificationCode.getByPhone(region, phone).then(function(verification) {
    var code, subtraction, timeDiff;
    if (verification) {
      timeDiff = Math.floor((Date.now() - verification.updatedAt.getTime()) / 1000);
      if (req.app.get('env') === 'development') {
        subtraction = moment().subtract(5, 's');
      } else {
        subtraction = moment().subtract(1, 'm');
      }
      if (subtraction.isBefore(verification.updatedAt)) {
        return res.send(new APIResult(5000, null, 'Throttle limit exceeded.'));
      }
    }
    code = _.random(1000, 9999);
    // code = 9999;
    if (req.app.get('env') === 'development') {
      return VerificationCode.upsert({
        region: region,
        phone: phone,
        sessionId: ''
      }).then(function() {
        return res.send(new APIResult(200));
      });
    } else if (Config.RONGCLOUD_SMS_REGISTER_TEMPLATE_ID !== '') {
      return rongCloud.sms.sendCode(region, phone, Config.RONGCLOUD_SMS_REGISTER_TEMPLATE_ID, function(err, resultText) {
        var result;
        if (err) {
          return next(err);
        }
        result = JSON.parse(resultText);
        if (result.code !== 200) {
          return next(new Error('RongCloud Server API Error Code: ' + result.code));
        }
        return VerificationCode.upsert({
          region: region,
          phone: phone,
          sessionId: result.sessionId
        }).then(function() {
          return res.send(new APIResult(200));
        });
      });
    }
  })["catch"](next);
});

router.post('/verify_code', function(req, res, next) {
  var code, phone, region;
  phone = req.body.phone;
  region = req.body.region;
  code = req.body.code;
  return VerificationCode.getByPhone(region, phone).then(function(verification) {
    if (!verification) {
      return res.status(404).send('Unknown phone number.');
    } else if (moment().subtract(2, 'm').isAfter(verification.updatedAt)) {
      return res.send(new APIResult(2000, null, 'Verification code expired.'));
    } else if ((req.app.get('env') === 'development' || Config.RONGCLOUD_SMS_REGISTER_TEMPLATE_ID === '') && code === '9999') {
      return res.send(new APIResult(200, {
        verification_token: verification.token
      }));
    } else {
      return rongCloud.sms.verifyCode(verification.sessionId, code, function(err, resultText) {
        var errorMessage, result;
        if (err) {
          errorMessage = err.message;
          if (errorMessage === 'Unsuccessful HTTP response' || errorMessage === 'Too Many Requests' || verification.sessionId === '') {
            return res.status(err.status).send(errorMessage);
          } else {
            return next(err);
          }
        }
        result = JSON.parse(resultText);
        if (result.code !== 200) {
          return next(new Error('RongCloud Server API Error Code: ' + result.code));
        }
        if (result.success) {
          return res.send(new APIResult(200, {
            verification_token: verification.token
          }));
        } else {
          return res.send(new APIResult(1000, null, 'Invalid verification code.'));
        }
      });
    }
  })["catch"](next);
});

router.post('/check_phone_available', function(req, res, next) {
  var phone, region;
  region = req.body.region;
  phone = req.body.phone;
  if (!validator.isMobilePhone(phone.toString(), regionMap[region])) {
    return res.status(400).send('Invalid region and phone number.');
  }
  return User.checkPhoneAvailable(region, phone).then(function(result) {
    if (result) {
      return res.send(new APIResult(200, true));
    } else {
      return res.send(new APIResult(200, false, 'Phone number has already existed.'));
    }
  })["catch"](next);
});

router.post('/register', function(req, res, next) {
  var nickname, password, verificationToken,region,phone;
  nickname = Utility.xss(req.body.nickname, NICKNAME_MAX_LENGTH);
  password = req.body.password;
  phone    = req.body.phone;
  verificationToken = req.body.verification_token;
  console.log(nickname,password,verificationToken);
  if (password.indexOf(' ') > 0) {
    return res.status(400).send('Password must have no space.');
  }
  if (!validator.isLength(nickname, NICKNAME_MIN_LENGTH, NICKNAME_MAX_LENGTH)) {
    return res.status(400).send('Length of nickname invalid.');
  }
  if (!validator.isLength(password, PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH)) {
    return res.status(400).send('Length of password invalid.');
  }
  /* if (!validator.isUUID(verificationToken)) {
    return res.status(400).send('Invalid verification_token.');
  } */
 /* return VerificationCode.getByToken(verificationToken).then(function(verification) {
    if (!verification) {
      return res.status(404).send('Unknown verification_token.');
    }
	console.log(verification); */
	region = 86;
    return User.checkPhoneAvailable(region, phone).then(function(result) {
      var hash, salt, openid;
      if (result) {
        salt = Utility.random(1000, 9999);
        hash = Utility.hash(password, salt);
        openid = Utility.hash(Date.now());// new Date().getTime() || Date.now()
        return sequelize.transaction(function(t) {
          return User.create({
            nickname: nickname,
            region: region,
            phone: phone,//verification
            passwordHash: hash,
            passwordSalt: salt.toString(),
            openId: openid
          }, {
            transaction: t
          }).then(function(user) {
			  // console.log(user);
            return DataVersion.create({
              userId: user.id,
              transaction: t
            }).then(function() {
              Session.setAuthCookie(res, user.id);
              Session.setNicknameToCache(user.id, nickname);
              return res.send(new APIResult(200, Utility.encodeResults({
                id: user.id
              })));
            });
          });
        });
      } else {
        return res.status(400).send('Phone number has already existed.');
      }
    })["catch"](next);
  /* })["catch"](next); */
});

router.post('/wechat_auth', function(req, res, next) {
  var nickname, password, verificationToken,region,phone,portraitUri,openId;
  nickname = Utility.xss(req.body.nickname, NICKNAME_MAX_LENGTH);
  portraituri = req.body.headurl;
  openId = req.body.wechatopenid;
  // return res.status(123).send('haha 111.');
  console.log('wechat_auth:',nickname,portraituri,openId);
  password = '123456';
  phone    = Date.now();
  if (password.indexOf(' ') > 0) {
    return res.status(400).send('Password must have no space.');
  }
  if (!validator.isLength(nickname, NICKNAME_MIN_LENGTH, NICKNAME_MAX_LENGTH)) {
    return res.status(400).send('Length of nickname invalid.');
  }
  if (!validator.isLength(password, PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH)) {
    return res.status(400).send('Length of password invalid.');
  }
  //search
  return User.findOne({
    where: {
      openId: openId
    },
    attributes: ['id', 'passwordHash', 'passwordSalt', 'nickname', 'portraitUri', 'rongCloudToken', 'userId', 'openId']
  }).then(function(user) {
    var errorMessage, passwordHash;
    errorMessage = 'Invalid phone or password.';
    if (!user) {
/*************** 注册 - start ************/
	// return res.send(new APIResult(1000, null, errorMessage));
	region = 86;
	var hash, salt;
	salt = Utility.random(1000, 9999);
	hash = Utility.hash(password, salt);
	return sequelize.transaction(function(t) {
	  return User.create({
		nickname: nickname,
		region: region,
		phone: phone,//verification
		portraitUri: portraituri,
		passwordHash: hash,
		passwordSalt: salt.toString(),
		openId: openId
	  }, {
		transaction: t
	  }).then(function(users) {
		  // console.log('123456_21',users.$modelOptions.indexes);
		if (!users) {
			return res.status(400).send('User register error.');
		}
		return DataVersion.create({
		  userId: users.id,
		  transaction: t
		}).then(function() {
		  // Session.setAuthCookie(res, users.id);
		  // Session.setNicknameToCache(users.id, nickname);
		  /*************** 登录 - start ************/
		  /* return User.update({
			userId: Utility.encodeId(users.id)
		  }, {
			where: {
			  id: users.id
			}
		  }).then(function() { */
			  // console.log('123456_21',users.id);
			  Session.setAuthCookie(res, users.id);
			  Session.setNicknameToCache(users.id, nickname);
              return res.send(new APIResult(2001, Utility.encodeResults({
                id: users.id
              })));
			  /* GroupMember.findAll({
				where: {
				  memberId: users.id
				},
				attributes: [],
				include: {
				  model: Group,
				  where: {
					deletedAt: null
				  },
				  attributes: ['id', 'name']
				}
			  }).then(function(groups) {
				var groupIdNamePairs;
				Utility.log('Sync groups: %j', groups);
				groupIdNamePairs = {};
				groups.forEach(function(group) {
				  return groupIdNamePairs[Utility.encodeId(group.group.id)] = group.group.name;
				});
				Utility.log('Sync groups: %j', groupIdNamePairs);
				return rongCloud.group.sync(Utility.encodeId(users.id), groupIdNamePairs, function(err, resultText) {
				  if (err) {
					return Utility.logError('Error sync user\'s group list failed: %s', err);
				  }
				});
			  })["catch"](function(error) {
				return Utility.logError('Sync groups error: ', error);
			  });
			  if (users.rongCloudToken === '') {
				if (req.app.get('env') === 'development') {
				  return res.send(new APIResult(2001, Utility.encodeResults({
					id: users.id,
					token: 'fake token'
				  })));
				}
				return getToken(users.id, users.nickname, users.portraitUri).then(function(token) {
				  return res.send(new APIResult(2001, Utility.encodeResults({
					id: users.id,
					token: token
				  })));
				});
			  } else {
				return res.send(new APIResult(2001, Utility.encodeResults({
				  id: users.id,
				  token: users.rongCloudToken
				})));
			  } */
		  /* }); */
		  /*************** 登录 - end ************/
		});
	  });
	});
  
/*************** 注册 - end ************/
    } else {
/*************** 登录 - start ************/
  // console.log('userid',user.id,Utility.encodeId(user.id),user.userId);
  return User.update({
    userId: Utility.encodeId(user.id)
  }, {
    where: {
      id: user.id
    }
  }).then(function() {
      if (openId !== user.openId) {
        return res.send(new APIResult(1000, null, errorMessage));
      }
      Session.setAuthCookie(res, user.id);
      Session.setNicknameToCache(user.id, user.nickname);
      GroupMember.findAll({
        where: {
          memberId: user.id
        },
        attributes: [],
        include: {
          model: Group,
          where: {
            deletedAt: null
          },
          attributes: ['id', 'name']
        }
      }).then(function(groups) {
        var groupIdNamePairs;
        Utility.log('Sync groups: %j', groups);
        groupIdNamePairs = {};
        groups.forEach(function(group) {
          return groupIdNamePairs[Utility.encodeId(group.group.id)] = group.group.name;
        });
        Utility.log('Sync groups: %j', groupIdNamePairs);
        return rongCloud.group.sync(Utility.encodeId(user.id), groupIdNamePairs, function(err, resultText) {
          if (err) {
            return Utility.logError('Error sync user\'s group list failed: %s', err);
          }
        });
      })["catch"](function(error) {
        return Utility.logError('Sync groups error: ', error);
      });
      if (user.rongCloudToken === '') {
        if (req.app.get('env') === 'development') {
          return res.send(new APIResult(200, Utility.encodeResults({
            id: user.id,
            token: 'fake token'
          })));
        }
        return getToken(user.id, user.nickname, user.portraitUri).then(function(token) {
          return res.send(new APIResult(200, Utility.encodeResults({
            id: user.id,
            token: token
          })));
        });
      } else {
        return res.send(new APIResult(200, Utility.encodeResults({
          id: user.id,
          token: user.rongCloudToken
        })));
      }
  });
/*************** 登录 - end ************/
	}
	
  })["catch"](next);
  //return res.status(400).send('Phone number has already existed.');
});

router.post('/wechat_auth_update_userid', function(req, res, next) {
  var userId,decodeuserId;
  userId = req.body.userId;
  if (!userId) {
    return res.status(400).send('Invalid region and phone number.');
  }
  decodeuserId = Utility.encodeId(userId);
  console.log('wechat_auth_update_userid:',userId,decodeuserId);
  return User.findOne({
    where: {
      id: userId
    },
    attributes: ['id', 'passwordHash', 'passwordSalt', 'nickname', 'portraitUri', 'rongCloudToken', 'userId']
  }).then(function(user) {
    var errorMessage;
    errorMessage = 'Invalid userId.';
    if (!user) {
      return res.send(new APIResult(1000, null, errorMessage));
    } else {
		
console.log('userid',userId,Utility.encodeId(userId),user.userId);
  return User.update({
    userId: Utility.encodeId(userId)
  }, {
    where: {
      id: userId
    }
  }).then(function() {
	
      Session.setAuthCookie(res, user.id);
      Session.setNicknameToCache(user.id, user.nickname);
      GroupMember.findAll({
        where: {
          memberId: user.id
        },
        attributes: [],
        include: {
          model: Group,
          where: {
            deletedAt: null
          },
          attributes: ['id', 'name']
        }
      }).then(function(groups) {
        var groupIdNamePairs;
        Utility.log('Sync groups: %j', groups);
        groupIdNamePairs = {};
        groups.forEach(function(group) {
          return groupIdNamePairs[Utility.encodeId(group.group.id)] = group.group.name;
        });
        Utility.log('Sync groups: %j', groupIdNamePairs);
        return rongCloud.group.sync(Utility.encodeId(user.id), groupIdNamePairs, function(err, resultText) {
          if (err) {
            return Utility.logError('Error sync user\'s group list failed: %s', err);
          }
        });
      })["catch"](function(error) {
        return Utility.logError('Sync groups error: ', error);
      });
      if (user.rongCloudToken === '') {
        if (req.app.get('env') === 'development') {
          return res.send(new APIResult(200, Utility.encodeResults({
            id: user.id,
            token: 'fake token'
          })));
        }
        return getToken(user.id, user.nickname, user.portraitUri).then(function(token) {
          return res.send(new APIResult(200, Utility.encodeResults({
            id: user.id,
            token: token
          })));
        });
      } else {
        return res.send(new APIResult(200, Utility.encodeResults({
          id: user.id,
          token: user.rongCloudToken
        })));
      }
  });
//***************************
    }
  })["catch"](next);
});	

router.post('/get_double_version', function(req, res, next) {
	var flagversion;// flag = 1 yes盖 flag = 0 no盖 
	return res.send(new APIResult(200, Utility.encodeResults({
          flag: 0
        })));
});

router.post('/get_double_version_new', function(req, res, next) {
	var flagversion;// flag = 1 yes盖 flag = 0 no盖 
	return res.send(new APIResult(200, Utility.encodeResults({
          flag: 1
        })));
});

router.post('/login', function(req, res, next) {
	/*res.header("Access-Control-Allow-Origin", "");
	   res.header("Access-Control-Allow-Headers", "X-Requested-With");
	   res.header("Access-Control-Allow-Methods","PUT,POST,GET,DELETE,OPTIONS");
	   res.header("X-Powered-By",' 3.2.1');
	   res.header("Content-Type", "application/json;charset=utf-8");*/
  var password, phone, region;
  region = req.body.region;
  phone = req.body.phone;
  password = req.body.password;
  // console.log(new Date().getTime());
  // console.log(Date.now());
  // console.log(Utility.hash(new Date().getTime()));
  // console.log(Utility.hash(new Date().getTime()).length);
  if (!validator.isMobilePhone(phone, regionMap[region])) {
    return res.status(400).send('Invalid region and phone number.');
  }
/************************/
/* return Blacklist.create({
	userId: currentUserId,
	friendId: userId,
	status: true,
	timestamp: timestamp
}).then(function() {
	Utility.log('Sync: fix user blacklist, add %s -> %s from db.', currentUserId, userId);
	return DataVersion.updateBlacklistVersion(currentUserId, timestamp);
}) */
/* return Reports.create({
	uid: 1,
	gid: 2,
	content: 1,
	timestamp: Date.now()
  }).then(function(reports) {
	  
  }); */
/************************/
  return User.findOne({
    where: {
      region: region,
      phone: phone
    },
    attributes: ['id', 'passwordHash', 'passwordSalt', 'nickname', 'portraitUri', 'rongCloudToken', 'userId']
  }).then(function(user) {
    var errorMessage, passwordHash;
    errorMessage = 'Invalid phone or password.';
    if (!user) {
      return res.send(new APIResult(1000, null, errorMessage));
    } else {
		
console.log('userid',user.id,Utility.encodeId(user.id),user.userId);
  return User.update({
    userId: Utility.encodeId(user.id)
  }, {
    where: {
      id: user.id
    }
  }).then(function() {
	
      passwordHash = Utility.hash(password, user.passwordSalt);
      if (passwordHash !== user.passwordHash) {
        return res.send(new APIResult(1000, null, errorMessage));
      }
      Session.setAuthCookie(res, user.id);
      Session.setNicknameToCache(user.id, user.nickname);
      GroupMember.findAll({
        where: {
          memberId: user.id
        },
        attributes: [],
        include: {
          model: Group,
          where: {
            deletedAt: null
          },
          attributes: ['id', 'name']
        }
      }).then(function(groups) {
        var groupIdNamePairs;
        Utility.log('Sync groups: %j', groups);
        groupIdNamePairs = {};
        groups.forEach(function(group) {
          return groupIdNamePairs[Utility.encodeId(group.group.id)] = group.group.name;
        });
        Utility.log('Sync groups: %j', groupIdNamePairs);
        return rongCloud.group.sync(Utility.encodeId(user.id), groupIdNamePairs, function(err, resultText) {
          if (err) {
            return Utility.logError('Error sync user\'s group list failed: %s', err);
          }
        });
      })["catch"](function(error) {
        return Utility.logError('Sync groups error: ', error);
      });
      if (user.rongCloudToken === '') {
        if (req.app.get('env') === 'development') {
          return res.send(new APIResult(200, Utility.encodeResults({
            id: user.id,
            token: 'fake token'
          })));
        }
        return getToken(user.id, user.nickname, user.portraitUri).then(function(token) {
          return res.send(new APIResult(200, Utility.encodeResults({
            id: user.id,
            token: token
          })));
        });
      } else {
        return res.send(new APIResult(200, Utility.encodeResults({
          id: user.id,
          token: user.rongCloudToken
        })));
      }
  });
//***************************
    }
  })["catch"](next);
});

router.post('/logout', function(req, res) {
  res.clearCookie(Config.AUTH_COOKIE_NAME);
  return res.send(new APIResult(200));
});

router.post('/reset_password', function(req, res, next) {
  var password, verificationToken;
  password = req.body.password;
  verificationToken = req.body.verification_token;
  if (password.indexOf(' ') !== -1) {
    return res.status(400).send('Password must have no space.');
  }
  if (!validator.isLength(password, PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH)) {
    return res.status(400).send('Length of password invalid.');
  }
  if (!validator.isUUID(verificationToken)) {
    return res.status(400).send('Invalid verification_token.');
  }
  return VerificationCode.getByToken(verificationToken).then(function(verification) {
    var hash, salt;
    if (!verification) {
      return res.status(404).send('Unknown verification_token.');
    }
    salt = _.random(1000, 9999);
    hash = Utility.hash(password, salt);
    return User.update({
      passwordHash: hash,
      passwordSalt: salt.toString()
    }, {
      where: {
        region: verification.region,
        phone: verification.phone
      }
    }).then(function() {
      return res.send(new APIResult(200));
    });
  })["catch"](next);
});

router.post('/change_password', function(req, res, next) {
  var newPassword, oldPassword;
  newPassword = req.body.newPassword;
  oldPassword = req.body.oldPassword;
  if (newPassword.indexOf(' ') !== -1) {
    return res.status(400).send('New password must have no space.');
  }
  if (!validator.isLength(newPassword, PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH)) {
    return res.status(400).send('Invalid new password length.');
  }
  return User.findById(Session.getCurrentUserId(req, {
    attributes: ['id', 'passwordHash', 'passwordSalt']
  })).then(function(user) {
    var newHash, newSalt, oldHash;
    oldHash = Utility.hash(oldPassword, user.passwordSalt);
    if (oldHash !== user.passwordHash) {
      return res.send(new APIResult(1000, null, 'Wrong old password.'));
    }
    newSalt = _.random(1000, 9999);
    newHash = Utility.hash(newPassword, newSalt);
    return user.update({
      passwordHash: newHash,
      passwordSalt: newSalt.toString()
    }).then(function() {
      return res.send(new APIResult(200));
    });
  })["catch"](next);
});

router.post('/set_nickname', function(req, res, next) {
  var currentUserId, nickname, timestamp;
  nickname = Utility.xss(req.body.nickname, NICKNAME_MAX_LENGTH);
  if (!validator.isLength(nickname, NICKNAME_MIN_LENGTH, NICKNAME_MAX_LENGTH)) {
    return res.status(400).send('Invalid nickname length.');
  }
  currentUserId = Session.getCurrentUserId(req);
  timestamp = Date.now();
  return User.update({
    nickname: nickname,
    timestamp: timestamp
  }, {
    where: {
      id: currentUserId
    }
  }).then(function() {
    rongCloud.user.refresh(Utility.encodeId(currentUserId), nickname, null, function(err, resultText) {
      var result;
      if (err) {
        Utility.logError('RongCloud Server API Error: ', err.message);
      }
      result = JSON.parse(resultText);
      if (result.code !== 200) {
        return Utility.logError('RongCloud Server API Error Code: ', result.code);
      }
    });
    Session.setNicknameToCache(currentUserId, nickname);
    return Promise.all([DataVersion.updateUserVersion(currentUserId, timestamp), DataVersion.updateAllFriendshipVersion(currentUserId, timestamp)]).then(function() {
      Cache.del("user_" + currentUserId);
      Cache.del("friendship_profile_user_" + currentUserId);
      Friendship.findAll({
        where: {
          userId: currentUserId
        },
        attributes: ['friendId']
      }).then(function(friends) {
        return friends.forEach(function(friend) {
          return Cache.del("friendship_all_" + friend.friendId);
        });
      });
      GroupMember.findAll({
        where: {
          memberId: currentUserId,
          isDeleted: false
        },
        attributes: ['groupId']
      }).then(function(groupMembers) {
        return groupMembers.forEach(function(groupMember) {
          return Cache.del("group_members_" + groupMember.groupId);
        });
      });
      return res.send(new APIResult(200));
    });
  })["catch"](next);
});

router.post('/set_portrait_uri', function(req, res, next) {
  var currentUserId, portraitUri, timestamp;
  portraitUri = Utility.xss(req.body.portraitUri, PORTRAIT_URI_MAX_LENGTH);
  if (!validator.isURL(portraitUri, {
    protocols: ['http', 'https'],
    require_protocol: true
  })) {
    return res.status(400).send('Invalid portraitUri format.');
  }
  if (!validator.isLength(portraitUri, PORTRAIT_URI_MIN_LENGTH, PORTRAIT_URI_MAX_LENGTH)) {
    return res.status(400).send('Invalid portraitUri length.');
  }
  currentUserId = Session.getCurrentUserId(req);
  timestamp = Date.now();
  return User.update({
    portraitUri: portraitUri,
    timestamp: timestamp
  }, {
    where: {
      id: currentUserId
    }
  }).then(function() {
    rongCloud.user.refresh(Utility.encodeId(currentUserId), null, portraitUri, function(err, resultText) {
      var result;
      if (err) {
        Utility.logError('RongCloud Server API Error: ', err.message);
      }
      result = JSON.parse(resultText);
      if (result.code !== 200) {
        return Utility.logError('RongCloud Server API Error Code: ', result.code);
      }
    });
    return Promise.all([DataVersion.updateUserVersion(currentUserId, timestamp), DataVersion.updateAllFriendshipVersion(currentUserId, timestamp)]).then(function() {
      Cache.del("user_" + currentUserId);
      Cache.del("friendship_profile_user_" + currentUserId);
      Friendship.findAll({
        where: {
          userId: currentUserId
        },
        attributes: ['friendId']
      }).then(function(friends) {
        return friends.forEach(function(friend) {
          return Cache.del("friendship_all_" + friend.friendId);
        });
      });
      GroupMember.findAll({
        where: {
          memberId: currentUserId,
          isDeleted: false
        },
        attributes: ['groupId']
      }).then(function(groupMembers) {
        return groupMembers.forEach(function(groupMember) {
          return Cache.del("group_members_" + groupMember.groupId);
        });
      });
      return res.send(new APIResult(200));
    });
  })["catch"](next);
});

router.post('/add_to_blacklist', function(req, res, next) {
  var currentUserId, encodedFriendId, friendId, timestamp;
  friendId = req.body.friendId;
  encodedFriendId = req.body.encodedFriendId;
  currentUserId = Session.getCurrentUserId(req);
  timestamp = Date.now();
  return User.checkUserExists(friendId).then(function(result) {
    if (result) {
      return rongCloud.user.blacklist.add(Utility.encodeId(currentUserId), encodedFriendId, function(err, resultText) {
        if (err) {
          return next(err);
        } else {
          return Blacklist.upsert({
            userId: currentUserId,
            friendId: friendId,
            status: true,
            timestamp: timestamp
          }).then(function() {
            return DataVersion.updateBlacklistVersion(currentUserId, timestamp).then(function() {
              Cache.del("user_blacklist_" + currentUserId);
              return res.send(new APIResult(200));
            });
          });
        }
      });
    } else {
      return res.status(404).send('friendId is not an available userId.');
    }
  })["catch"](next);
});

router.post('/remove_from_blacklist', function(req, res, next) {
  var currentUserId, encodedFriendId, friendId, timestamp;
  friendId = req.body.friendId;
  encodedFriendId = req.body.encodedFriendId;
  currentUserId = Session.getCurrentUserId(req);
  timestamp = Date.now();
  return rongCloud.user.blacklist.remove(Utility.encodeId(currentUserId), encodedFriendId, function(err, resultText) {
    if (err) {
      return next(err);
    } else {
      return Blacklist.update({
        status: false,
        timestamp: timestamp
      }, {
        where: {
          userId: currentUserId,
          friendId: friendId
        }
      }).then(function() {
        return DataVersion.updateBlacklistVersion(currentUserId, timestamp).then(function() {
          Cache.del("user_blacklist_" + currentUserId);
          return res.send(new APIResult(200));
        });
      })["catch"](next);
    }
  });
});

router.post('/upload_contacts', function(req, res, next) {
  var contacts;
  contacts = req.body;
  return res.status(404).send('Not implements.');
});

router.get('/get_token', function(req, res, next) {
  return User.findById(Session.getCurrentUserId(req, {
    attributes: ['id', 'nickname', 'portraitUri']
  })).then(function(user) {
    return getToken(user.id, user.nickname, user.portraitUri).then(function(token) {
      return res.send(new APIResult(200, Utility.encodeResults({
        userId: user.id,
        token: token
      }, 'userId')));
    });
  })["catch"](next);
});

router.get('/get_image_token', function(req, res, next) {
  var putPolicy, token;
  qiniu.conf.ACCESS_KEY = Config.QINIU_ACCESS_KEY;
  qiniu.conf.SECRET_KEY = Config.QINIU_SECRET_KEY;
  putPolicy = new qiniu.rs.PutPolicy(Config.QINIU_BUCKET_NAME);
  token = putPolicy.token();
  return res.send(new APIResult(200, {
    target: 'qiniu',
    domain: Config.QINIU_BUCKET_DOMAIN,
    token: token
  }));
});

router.post('/file_upload', function(req, res, next) {
  console.log('file_upload');
  console.log(req.body);
  console.log(req.files);
  console.log(req.files.img);
  /* 获得文件的临时路径 */
  var tmp_path = req.files.img.path;
  /* 指定文件上传后的目录 - 示例为"images"目录。  */
  var target_path = './public/header/' + req.files.img.name;
  console.log(target_path);
  /* 移动文件 */
  fs.rename(tmp_path, target_path, function(err) {
    if (err) throw err;
    /* 删除临时文件夹文件,  */
    fs.unlink(tmp_path, function() {
      if (err) throw err;
		return res.send('File uploaded to: ' + target_path + ' - ' + req.files.img.size + ' bytes');
	});
  });
  // return res.send(new APIResult(200, {
    // token: 'file_upload'
  // }));
});

router.get('/get_sms_img_code', function(req, res, next) {
  rongCloud.sms.getImgCode(Config.RONGCLOUD_APP_KEY, function(err, resultText) {
    var result;
    if (err) {
      return next(err);
    }
    result = JSON.parse(resultText);
    if (result.code !== 200) {
      return next(new Error('RongCloud Server API Error Code: ' + result.code));
    }
  });
  return res.send(new APIResult(200, {
    url: result.url,
    verifyId: result.verifyId
  }));
});

router.get('/blacklist', function(req, res, next) {
  var currentUserId, timestamp;
  currentUserId = Session.getCurrentUserId(req);
  timestamp = Date.now();
  return Cache.get("user_blacklist_" + currentUserId).then(function(blacklist) {
    if (blacklist) {
      return res.send(new APIResult(200, blacklist));
    } else {
      return Blacklist.findAll({
        where: {
          userId: currentUserId,
          friendId: {
            $ne: 0
          },
          status: true
        },
        attributes: [],
        include: {
          model: User,
          attributes: ['id', 'nickname', 'portraitUri', 'updatedAt']
        }
      }).then(function(dbBlacklist) {
        var results;
        rongCloud.user.blacklist.query(Utility.encodeId(currentUserId), function(err, resultText) {
          var dbBlacklistUserIds, hasDirtyData, result, serverBlacklistUserIds;
          if (err) {
            return Utility.logError('Error: request server blacklist failed: %s', err);
          } else {
            result = JSON.parse(resultText);
            if (result.code === 200) {
              hasDirtyData = false;
              serverBlacklistUserIds = result.users;
              dbBlacklistUserIds = dbBlacklist.map(function(blacklist) {
                if (blacklist.user) {
                  return blacklist.user.id;
                } else {
                  hasDirtyData = true;
                  return null;
                }
              });
              if (hasDirtyData) {
                Utility.log('Dirty blacklist data %j', dbBlacklist);
              }
              serverBlacklistUserIds.forEach(function(encodedUserId) {
                var userId;
                userId = Utility.decodeIds(encodedUserId);
                if (dbBlacklistUserIds.indexOf(userId) === -1) {
                  return Blacklist.create({
                    userId: currentUserId,
                    friendId: userId,
                    status: true,
                    timestamp: timestamp
                  }).then(function() {
                    Utility.log('Sync: fix user blacklist, add %s -> %s from db.', currentUserId, userId);
                    return DataVersion.updateBlacklistVersion(currentUserId, timestamp);
                  })["catch"](function() {});
                }
              });
              return dbBlacklistUserIds.forEach(function(userId) {
                if (userId && serverBlacklistUserIds.indexOf(Utility.encodeId(userId)) === -1) {
                  return Blacklist.update({
                    status: false,
                    timestamp: timestamp
                  }, {
                    where: {
                      userId: currentUserId,
                      friendId: userId
                    }
                  }).then(function() {
                    Utility.log('Sync: fix user blacklist, remove %s -> %s from db.', currentUserId, userId);
                    return DataVersion.updateBlacklistVersion(currentUserId, timestamp);
                  });
                }
              });
            }
          }
        });
        results = Utility.encodeResults(dbBlacklist, [['user', 'id']]);
        Cache.set("user_blacklist_" + currentUserId, results);
        return res.send(new APIResult(200, results));
      });
    }
  })["catch"](next);
});

router.get('/groups', function(req, res, next) {
  var currentUserId;
  currentUserId = Session.getCurrentUserId(req);
  return Cache.get("user_groups_" + currentUserId).then(function(groups) {
    if (groups) {
      return res.send(new APIResult(200, groups));
    } else {
      return GroupMember.findAll({
        where: {
          memberId: currentUserId
        },
        attributes: ['role'],
        include: [
          {
            model: Group,
            attributes: ['id', 'name', 'portraitUri', 'creatorId', 'memberCount', 'maxMemberCount']
          }
        ]
      }).then(function(groups) {
        var results;
        results = Utility.encodeResults(groups, [['group', 'id'], ['group', 'creatorId']]);
        Cache.set("user_groups_" + currentUserId, results);
        return res.send(new APIResult(200, results));
      });
    }
  })["catch"](next);
});

router.get('/sync/:version', function(req, res, next) {
  var blacklist, currentUserId, friends, groupMembers, groups, maxVersions, user, version;
  version = req.params.version;
  if (!validator.isInt(version)) {
    return res.status(400).send('Version parameter is not integer.');
  }
  user = blacklist = friends = groups = groupMembers = null;
  maxVersions = [];
  currentUserId = Session.getCurrentUserId(req);
  return DataVersion.findById(currentUserId).then(function(dataVersion) {
    return co(function*() {
      var groupIds, group_members;
      if (dataVersion.userVersion > version) {
        user = (yield User.findById(currentUserId, {
          attributes: ['id', 'nickname', 'portraitUri', 'timestamp']
        }));
      }
      if (dataVersion.blacklistVersion > version) {
        blacklist = (yield Blacklist.findAll({
          where: {
            userId: currentUserId,
            timestamp: {
              $gt: version
            }
          },
          attributes: ['friendId', 'status', 'timestamp'],
          include: [
            {
              model: User,
              attributes: ['id', 'nickname', 'portraitUri']
            }
          ]
        }));
      }
      if (dataVersion.friendshipVersion > version) {
        friends = (yield Friendship.findAll({
          where: {
            userId: currentUserId,
            timestamp: {
              $gt: version
            }
          },
          attributes: ['friendId', 'displayName', 'status', 'timestamp'],
          include: [
            {
              model: User,
              attributes: ['id', 'nickname', 'portraitUri']
            }
          ]
        }));
      }
      if (dataVersion.groupVersion > version) {
        groups = (yield GroupMember.findAll({
          where: {
            memberId: currentUserId,
            timestamp: {
              $gt: version
            }
          },
          attributes: ['groupId', 'displayName', 'role', 'isDeleted'],
          include: [
            {
              model: Group,
              attributes: ['id', 'name', 'portraitUri', 'timestamp']
            }
          ]
        }));
      }
      if (groups) {
        groupIds = groups.map(function(group) {
          return group.group.id;
        });
      } else {
        groupIds = [];
      }
      if (dataVersion.groupVersion > version) {
        groupMembers = (yield GroupMember.findAll({
          where: {
            groupId: {
              $in: groupIds
            },
            timestamp: {
              $gt: version
            }
          },
          attributes: ['groupId', 'memberId', 'displayName', 'role', 'isDeleted', 'timestamp'],
          include: [
            {
              model: User,
              attributes: ['id', 'nickname', 'portraitUri']
            }
          ]
        }));
      }
      if (user) {
        maxVersions.push(user.timestamp);
      }
      if (blacklist) {
        maxVersions.push(_.max(blacklist, function(item) {
          return item.timestamp;
        }).timestamp);
      }
      if (friends) {
        maxVersions.push(_.max(friends, function(item) {
          return item.timestamp;
        }).timestamp);
      }
      if (groups) {
        maxVersions.push(_.max(groups, function(item) {
          return item.group.timestamp;
        }).group.timestamp);
      }
      if (groupMembers) {
        maxVersions.push(_.max(groupMembers, function(item) {
          return item.timestamp;
        }).timestamp);
      }
      if (blacklist === null) {
        blacklist = [];
      }
      if (friends === null) {
        friends = [];
      }
      if (groups === null) {
        groups = [];
      }
      if (group_members === null) {
        group_members = [];
      }
      Utility.log('maxVersions: %j', maxVersions);
      return res.send(new APIResult(200, {
        version: _.max(maxVersions),
        user: user,
        blacklist: blacklist,
        friends: friends,
        groups: groups,
        group_members: groupMembers
      }));
    });
  })["catch"](next);
});

router.get('/batch', function(req, res, next) {
  var ids;
  ids = req.query.id;
  if (!Array.isArray(ids)) {
    ids = [ids];
  }
  ids = Utility.decodeIds(ids);
  return User.findAll({
    where: {
      id: {
        $in: ids
      }
    },
    attributes: ['id', 'nickname', 'portraitUri']
  }).then(function(users) {
    return res.send(new APIResult(200, Utility.encodeResults(users)));
  })["catch"](next);
});

router.get('/:id', function(req, res, next) {
  var userId;
  userId = req.params.id;
  userId = Utility.decodeIds(userId);
  return Cache.get("user_" + userId).then(function(user) {
    if (user) {
      return res.send(new APIResult(200, user));
    } else {
      return User.findById(userId, {
        attributes: ['id', 'nickname', 'portraitUri']
      }).then(function(user) {
        var results;
        if (!user) {
          return res.status(404).send('Unknown user.');
        }
        results = Utility.encodeResults(user);
        Cache.set("user_" + userId, results);
        return res.send(new APIResult(200, results));
      });
    }
  })["catch"](next);
});

router.get('/find/:type/:region/:phone/:userid', function(req, res, next) {
  var type, userid, phone, region;
  region = req.params.region;
  phone = req.params.phone;
  type = req.params.type;
  userid = req.params.userid;
  if (!validator.isMobilePhone(phone, regionMap['86'])) {
	  type = 2;
  } else {
	  type = 1;
  }
  if(type == 1){
	  if (!validator.isMobilePhone(phone, regionMap[region])) {
		return res.status(400).send('Invalid region and phone number.');
	  }
	  return User.findOne({
		where: {
		  region: region,
		  phone: phone
		},
		attributes: ['id', 'nickname', 'portraitUri']
	  }).then(function(user) {
		if (!user) {
		  return res.status(404).send('Unknown user.');
		}
		return res.send(new APIResult(200, Utility.encodeResults(user)));
	  })["catch"](next);
  }else if(type == 2){
	  if (!userid) {
		return res.status(400).send('Invalid userid.');
	  }
	  userid = Utility.decodeIds(userid);
	  return User.findOne({
		where: {
		  id: userid
		},
		attributes: ['id', 'nickname', 'portraitUri']
	  }).then(function(user) {
		if (!user) {
		  return res.status(404).send('Unknown user.');
		}
		return res.send(new APIResult(200, Utility.encodeResults(user)));
	  })["catch"](next);
  }
});

module.exports = router;

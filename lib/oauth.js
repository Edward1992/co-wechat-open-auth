'use strict';

const httpx = require('httpx');

const querystring = require('querystring');
const wxcrypto = require('./WXC');
const parseString = require('xml2js').parseString;

class ComponentAccessToken {
  constructor(data) {
    this.component_access_token = data.component_access_token;
    this.expires_at = data.expires_at;
  }

  /*!
   * 检查AccessToken是否有效，检查规则为当前时间和过期时间进行对比
   *
   * Examples:
   * ```
   * token.isValid();
   * ```
   */
  isValid() {
    return !!this.component_access_token && (new Date().getTime()) < this.expires_at;
  }
}

/**
 * @param {String} appid 在开放平台申请得到的第三方平台appid
 * @param {String} appsecret 在开放平台申请得到的第三方平台appsecret
 * @param {String} aesToken 公众号消息校验Token
 * @param {String} aesKey 公众号消息加解密Key
 * @param {Function} saveVerifyTicket 保存全局component_verify_ticket的方法，建议存放在缓存中, 必填项
 * @param {Function} getVerifyTicket 获取全局component_verify_ticket的方法，建议存放在缓存中, 必填项
 * @param {Function} getComponentToken 获取全局component_access_token的方法，选填项，多进程状态下应该存放在缓存中
 * @param {Function} saveComponentToken 获取全局component_access_token的方法，选填项，多进程状态下应该存放在缓存中
 */
class OpenAuth {
  constructor(appid, appsecret, aesToken, aesKey, saveVerifyTicket, getVerifyTicket, getComponentToken, saveComponentToken) {
    this.appid = appid;
    this.appsecret = appsecret;
    this.aesToken = aesToken;
    this.aesKey = aesKey;
    // token的获取和存储
    this.store = {};
    this.getVerifyTicket = getVerifyTicket;
    this.saveVerifyTicket = saveVerifyTicket;
    this.getComponentToken = getComponentToken || async function (openid) {
      return this.store[openid];
    };
    if (!saveToken && process.env.NODE_ENV === 'production') {
      console.warn('Please dont save oauth token into memory under production');
    }
    this.saveComponentToken = saveComponentToken || async function (openid, token) {
      this.store[openid] = token;
    };
    this.prefix = 'https://api.weixin.qq.com/cgi-bin/component/';
    this.snsPrefix = 'https://api.weixin.qq.com/sns/';
    this.defaults = {};
  }

  /**
   * 用于设置urllib的默认options
   *
   * Examples:
   * ```
   * oauth.setOpts({timeout: 15000});
   * ```
   * @param {Object} opts 默认选项
   */
  setOpts(opts) {
    this.defaults = opts;
  }

  /*!
   * urllib的封装
   *
   * @param {String} url 路径
   * @param {Object} opts urllib选项
   */
  async request(url, opts = {}) {
    var options = Object.assign({}, this.defaults);
    for (var key in opts) {
      if (key !== 'headers') {
        options[key] = opts[key];
      } else {
        if (opts.headers) {
          options.headers = options.headers || {};
          Object.assign(options.headers, opts.headers);
        }
      }
    }

    var data;
    try {
      var response = await httpx.request(url, options);
      var text = await httpx.read(response, 'utf8');
      data = JSON.parse(text);
    } catch (err) {
      err.name = 'WeChatAPI' + err.name;
      throw err;
    }

    if (data.errcode) {
      var err = new Error(data.errmsg);
      err.name = 'WeChatAPIError';
      err.code = data.errcode;
      throw err;
    }

    return data;
  }

  async getComponentAccessToken() {
    const url = this.prefix + 'api_component_token';
    const verifyTicket = await this.getVerifyTicket();

    const params = {
      component_appid: this.appid,
      component_appsecret: this.appsecret,
      component_verify_ticket: verifyTicket
    };
    const args = {
      method: 'post',
      data: params,
      dataType: 'json',
      contentType: 'json'
    };
    const token = await this.request(url, args); 
    const expireTime = (new Date().getTime()) + (token.expires_in - 100) * 1000;
    token.expires_at = expireTime;
    await this.saveComponentToken(token);
    return token;
  };
  
  
  /*!
   * 需要component_access_token的接口调用如果采用preRequest进行封装后，就可以直接调用。
   * 无需依赖getComponentAccessToken为前置调用。
   * 应用开发者无需直接调用此API。
   *
   * Examples:
   * ```
   * auth.preRequest(method, arguments);
   * ```
   * @param {Function} method 需要封装的方法
   */
  async preRequest(method, args = [], retryed) {
    // 调用用户传入的获取token的异步方法，获得token之后使用（并缓存它）。
    const token = await this.getComponentToken();
    const accessToken = new ComponentAccessToken(token);

    // 有token并且token有效直接调用
    if (token && accessToken.isValid()) {
      // 暂时保存token
      this.token = token;
      if (!retryed) {
        const retryHandle = async data => {
          // 40001 重试
          if (data && data.errcode && data.errcode === 40001) {
            await this.preRequest(method, args, true);
          }
        };

        const data = await method.call(this, args);
        await retryHandle(data);
      } else {
        await method.call(this, args);
      }
    } else {
      // 从微信获取获取token
      const token = await this.getComponentAccessToken();
      // 暂时保存token
      this.token = token;
      await method.call(this, args);
    };
  };
  
  
  /*
   * 获取最新的component_access_token
   * 该接口用于开发者调用
   *
   * Examples:
   * ```
   * auth.getLatestComponentToken(callback);
   * ```
   * callback:
   *
   * - `err`, 出现异常时的异常对象
   * - `token`, 获取的component_access_token
   *
   */
  async getLatestComponentToken() {
    // 调用用户传入的获取token的异步方法，获得token之后使用（并缓存它）。
    const token = await this.getComponentToken();
    const accessToken = new ComponentAccessToken(token);
    if (token && accessToken.isValid()) {
      return token;
    } else {
      // 使用appid/appsecret获取token
      return await this.getComponentAccessToken();
    };
  };
  
  
  /*
   * 获取预授权码pre_auth_code
   * 
   * Result:
   * ```
   * {"pre_auth_code": "PRE_AUTH_CODE", "expires_in": 600}
   * ```
   * 开发者需要检查预授权码是否过期
   *
   */
  async getPreAuthCode() {
    return await this.preRequest(this._getPreAuthCode);
  };
  
  /*!
   * 获取预授权码的未封装版本
   */
  _getPreAuthCode() {
    const url = this.prefix + 'api_create_preauthcode?component_access_token=' + this.token.component_access_token;
    const params = {
      component_appid: this.appid
    };
    var args = {
      method: 'post',
      data: params,
      dataType: 'json',
      contentType: 'json'
    };
    return this.request(url, args);
  };
  
  
  /*
   * 使用授权码换取公众号的接口调用凭据和授权信息
   * 这个接口需要在用户授权回调URI中调用，拿到用户公众号的调用
   * 凭证并保持下来（缓存or数据库）
   * 仅需在授权的时候调用一次
   *
   * Result:
   * ```
   * {
   *   "authorization_info": {
   *     "authorizer_appid": "wxf8b4f85f3a794e77",
   *     "authorizer_access_token": "AURH_ACCESS_CODE",
   *     "expires_in": 7200,
   *     "authorizer_refresh_token": "AUTH_REFRESH_TOKEN",
   *     "func_info": [
   *     ]
   *   }
   * }
   *
   * @param {String} auth_code 授权码
   */
  async getAuthToken(auth_code) {
    return await this.preRequest(this._getAuthToken, arguments);
  };
  
  /*!
   * 获取授权信息的未封装版本
   */
  _getAuthToken(auth_code) {
    const url = this.prefix + 'api_query_auth?component_access_token=' + this.token.component_access_token;
    const params = {
      component_appid: this.appid,
      authorization_code: auth_code
    };
    const args = {
      method: 'post',
      data: params,
      dataType: 'json',
      contentType: 'json'
    };
    return this.request(url, args);
  };
  
  
  
  /*
   * 获取（刷新）授权公众号的接口调用凭据（Token）
   * 这个接口应该由自动刷新授权授权方令牌的代码调用
   *
   * Result:
   * ```
   * {
   *   "authorizer_access_token": "AURH_ACCESS_CODE",
   *   "expires_in": 7200,
   *   "authorizer_refresh_token": "AUTH_REFRESH_TOKEN",
   * }
   *
   * @param {String} authorizer_appid 授权方appid
   * @param {String} authorizer_refresh_token 授权方的刷新令牌
   */
  async refreshAuthToken(authorizer_appid, authorizer_refresh_token) {
    return await this.preRequest(this._refreshAuthToken, arguments); 
  };
  
  /*!
   * 未封装的刷新接口调用凭据接口
   */
  _refreshAuthToken(authorizer_appid, authorizer_refresh_token) {
    const url = this.prefix + 'api_authorizer_token?component_access_token=' + this.token.component_access_token;
    const params = {
      component_appid: this.appid,
      authorizer_appid: authorizer_appid,
      authorizer_refresh_token: authorizer_refresh_token
    };
    const args = {
      method: 'post',
      data: params,
      dataType: 'json',
      contentType: 'json'
    };
    return this.request(url, args);
  };
  
  
  /*
   * 获取授权方的公众账号基本信息
   *
   * @param {String} authorizer_appid 授权方appid
   */
  async getAuthInfo(authorizer_appid) {
    return await this.preRequest(this._getAuthInfo, arguments);
  };
  
  /*!
   * 未封装的获取公众账号基本信息接口
   */
  _getAuthInfo(authorizer_appid) {
    const url = this.prefix + 'api_get_authorizer_info?component_access_token=' + this.token.component_access_token;
    const params = {
      component_appid: this.appid,
      authorizer_appid: authorizer_appid
    };
    const args = {
      method: 'post',
      data: params,
      dataType: 'json',
      contentType: 'json'
    };
    return this.request(url, args);
  };
  
  
  /*
   * 获取授权方的选项设置信息
   *
   * @param {String} authorizer_appid 授权方appid
   * @param {String} option_name 选项名称
   */
  async getAuthOption(authorizer_appid, option_name) {
    return await this.preRequest(this._getAuthOption, arguments);
  };
  
  /*!
   * 未封装的获取授权方选项信息
   */
  _getAuthOption(authorizer_appid, option_name) {
    const url = this.prefix + 'api_get_authorizer_option?component_access_token=' + this.token.component_access_token;
    const params = {
      component_appid: this.appid,
      authorizer_appid: authorizer_appid,
      option_name: option_name
    };
    const args = {
      method: 'post',
      data: params,
      dataType: 'json',
      contentType: 'json'
    };
    return this.request(url, args);
  };
  
  
  /*
   * 设置授权方的选项信息
   *
   * @param {String} authorizer_appid 授权方appid
   * @param {String} option_name 选项名称
   * @param {String} option_value 选项值
   * @param {Function} callback 回调函数
   */
  async setAuthOption(authorizer_appid, option_name, option_value) {
    return await this.preRequest(this._setAuthOption, arguments);
  };
  
  /*!
   * 未封装的设置授权方选项信息
   */
  _setAuthOption(authorizer_appid, option_name, option_value) {
    const url = this.prefix + 'api_set_authorizer_option?component_access_token=' + this.token.component_access_token;
    const params = {
      component_appid: this.appid,
      authorizer_appid: authorizer_appid,
      option_name: option_name,
      option_value: option_value
    };
    const args = {
      method: 'post',
      data: params,
      dataType: 'json',
      contentType: 'json'
    };
    return this.request(url, args, wrapper(callback));
  };

  /**
   * 获取用户授权页面的URL地址
   * @param {String} pre_auth_code 预授权码
   * @param {String} redirect 回调URI
   */
  getOpenAuthorizeURL(pre_auth_code, redirect) {
    const url = 'https://mp.weixin.qq.com/cgi-bin/componentloginpage?' + 
    'component_appid=' + this.appid  +
    '&pre_auth_code=' + pre_auth_code + 
    '&redirect_uri=' + redirect;
    
    return url;
  };

  async authEvent(body) {
    const newCrypto = new wxcrypto(this.aesToken, this.aesKey, this.appid);
    const bodyJson = await new Promise((resolve, reject) => {
      parseString(body, {explicitArray : false}, (err, result) => {
        resolve(result);
      });
    });
    console.log('bodyJson:', JSON.stringify(bodyJson));
    const encryptXml = newCrypto.decrypt(bodyJson.xml.Encrypt).message;
    console.log('encryptXml:', encryptXml);
    const encryptJson = await new Promise((resolve, reject) => {
      parseString(encryptXml, {explicitArray : false}, function (err, result) {
        resolve(result);
      });
    });
    console.log('encryptJson:', JSON.stringify(encryptJson));
    await this.saveVerifyTicket(encryptJson.xml.ComponentVerifyTicket);
  };

  /****************** 以下是网页授权相关的接口******************/

  /**
   * 获取授权页面的URL地址
   * @param {String} appid 授权公众号的appid
   * @param {String} redirect 授权后要跳转的地址
   * @param {String} state 开发者可提供的数据
   * @param {String} scope 作用范围，值为snsapi_userinfo和snsapi_base，前者用于弹出，后者用于跳转
   */
  getOAuthURL(appid, redirect, state, scope) {
    const url = 'https://open.weixin.qq.com/connect/oauth2/authorize';
    const info = {
      appid: appid,
      redirect_uri: redirect,
      response_type: 'code',
      scope: scope || 'snsapi_base',
      state: state || '',
      component_appid: this.appid
    };

    return url + '?' + querystring.stringify(info) + '#wechat_redirect';
  };


  /*
  * 根据授权获取到的code，换取access_token和openid
  *
  * @param {String} appid 授权公众号的appid
  * @param {String} code 授权获取到的code
  */
  async getOAuthAccessToken(appid, code) {
    return await this.preRequest(this._getOAuthAccessToken, arguments);
  };

  /*!
  * 未封装的获取网页授权access_token方法
  */
  _getOAuthAccessToken(appid, code) {
    const url = this.snsPrefix + 'oauth2/component/access_token';
    const params = {
      appid: appid,
      code: code,
      grant_type: 'authorization_code',
      component_appid: this.appid,
      component_access_token: this.token.component_access_token
    };
    const args = {
      method: 'get',
      data: params,
      dataType: 'json'
    };
    return this.request(url, args);
  };


  /*
  * 刷新网页授权的access_token
  *
  * @param {String} appid 授权公众号的appid
  * @param {String} refresh_token 授权刷新token
  */
  async refreshOAuthAccessToken(appid, refresh_token) {
    return await this.preRequest(this._refreshOAuthAccessToken, arguments);
  };

  /*!
  * 未封装的刷新网页授权access_token方法
  */
  _refreshOAuthAccessToken(appid, refresh_token) {
    const url = this.snsPrefix + 'oauth2/component/refresh_token';
    const params = {
      appid: appid,
      refresh_token: refresh_token,
      grant_type: 'refresh_token',
      component_appid: this.appid,
      component_access_token: this.token.component_access_token
    };
    const args = {
      method: 'get',
      data: params,
      dataType: 'json'
    };
    return this.request(url, args);
  };


  /*
  * 通过access_token获取用户基本信息
  *
  * @param {String} openid 授权用户的唯一标识
  * @param {String} access_token 网页授权接口调用凭证
  * @param {String} lang 返回国家地区语言版本，zh_CN 简体，zh_TW 繁体，en 英语
  */
  async getUserInfo(openid, access_token, lang) {
    const url = this.snsPrefix + 'userinfo';
    const params = {
      openid: openid,
      access_token: access_token,
      lang: lang || 'en'
    };
    const args = {
      method: 'get',
      data: params,
      dataType: 'json'
    };
    return this.request(url, args);
  };
}

module.exports = OpenAuth;

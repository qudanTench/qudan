package com.zhangheng.springboot.controller;

import com.zhangheng.springboot.entrty.Audience;
import com.zhangheng.springboot.feign.UserInfoFeign;
//import com.zhangheng.springboot.handler.UrlAccessDecisionManager;
import com.zhangheng.springboot.utils.JwtUtil;
import com.zhangheng.springboot.utils.YHResult;
import io.jsonwebtoken.Claims;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by 蜡笔小新不爱吃青椒 on 2018/8/3.
 */


@RestController
@RefreshScope//刷新配置
@RequestMapping("/qudanZuul/user")//窄化请求地址
@Api(value = "qudan-zuul", description = "用户信息")
public class VUserInfoController {

    /**
     * 注入用户相关
     *
     */
    @Autowired
    private UserInfoFeign userInfoFeign;
    @Autowired
    private Audience audience;


    //日志
    private final static Logger logger = LoggerFactory.getLogger(VUserInfoController.class);

    /**
     *前端用户登录接口
     */
    @ApiOperation(value = "登录获取token", response = String.class, notes = "用户信息", httpMethod = "POST")
    @ApiImplicitParams({
//            @ApiImplicitParam(paramType = "query", required = true, name = "username", dataType = "String", value = "用户名"),
            @ApiImplicitParam(paramType = "query", required = true, name = "userId", dataType = "String", value = "用户id"),
    })
    @PostMapping("/login")
    public YHResult appLogin(
//              @RequestBody Map<String,Object> params,
//            @RequestParam(value = "username", required = true) String username,
            @RequestParam(value = "userId", required = true) String userId,
            HttpServletRequest request
      ){
          try {
              long ttlMillis = 1000 * 60;//过期时间
              String token  = JwtUtil.createJWT(userId, "qudan", "趣单",ttlMillis,"");
              Map<String,Object> params = new HashMap<>();
              params.put("token",token);
//              YHResult appLogin = userInfoFeign.appLogin(params.get("username")+"", params.get("password")+"");
              return YHResult.build(200,"登录成功!",params);
          }catch (Exception e){
              logger.error(e.getMessage());
              logger.error("login 异常!");
              return YHResult.build(500,"接口异常!");
          }
      }
}

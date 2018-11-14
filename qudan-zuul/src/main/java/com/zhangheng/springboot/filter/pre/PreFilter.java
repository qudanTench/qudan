package com.zhangheng.springboot.filter.pre;

import com.alibaba.fastjson.JSONObject;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.zhangheng.springboot.controller.VUserInfoController;
import com.zhangheng.springboot.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.util.Map;

/**
 * Created by 蜡笔小新不爱吃青椒 on 2018/7/23.
 *
 * 请求路由之前被过滤 是否存在accessToken 存在就通过 不存在则过滤
 *
 */
public class PreFilter extends ZuulFilter{


    //日志
    private final static Logger logger = LoggerFactory.getLogger(PreFilter.class);


    /**
     * 返回一个字符代表过滤器的类型，在zuul中定义了四种不同生命周期的过滤器类型。
     * pre:可以在请求被路由之前调用。
     * routing:在路由请求时候被调用。
     * post:在routing和error过滤器之后被调用。
     * error:处理请求时发生错误被调用。
     * @return
     */
    @Override
    public String filterType() {

//        logger.info("过滤前被调用!!!");

        return "pre";
    }

    /**
     * 通过int定义过滤器执行的顺序
     * 数字越小表示优先级越高
     * @return
     */
    @Override
    public int filterOrder() {
        return 0;
    }

    /**
     * 返回一个boolean类型来判断该过滤器是否执行，从而该方法相当于是一个过滤器的开关。
     * @return
     */
    @Override
    public boolean shouldFilter() {
        return true;
    }

    /**
     * 过滤器的具体逻辑
     * @return
     */
    @Override
    public Object run() {
        logger.info("过滤前被调用!!!");
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();
        logger.info(String.format("%s request to %s", request.getMethod(), request.getRequestURL().toString()));
        String authHeader = request.getHeader("authorization");
        if(!StringUtils.isEmpty(authHeader)) {
            String token = authHeader.replace("Bearer ", "");
            Claims claims = JwtUtil.getClaims(token);
            if(claims!=null){
                try {
                    logger.info("access token ok" + claims.toString());
                    PrintWriter out = ctx.getResponse().getWriter();
                    out.write(getJsonTokenIsOk(ctx,claims));
                    out.flush();
                    out.close();
                }catch (Exception e){

                }
                return null;
            }else{
                logger.warn("accessToken验证不通过!!!");
                //设置不过滤该请求。并且返回错误码
                ctx.setSendZuulResponse(false);
                ctx.setResponseStatusCode(401);
                try {
                    ctx.getResponse().setContentType("text/html;charset=UTF-8");
                    ctx.getResponse().setCharacterEncoding("UTF-8");
                    ctx.getResponse().getWriter().write("accessToken验证不通过!!!");
                }catch (Exception e){

                }
                return null;
            }
        }else{
            logger.warn("accessToken is empty");
            //设置不过滤该请求。并且返回错误码
            ctx.setSendZuulResponse(false);
            ctx.setResponseStatusCode(401);
            try {
                PrintWriter out = ctx.getResponse().getWriter();
                out.write(getJsonTokenIsEmpty(ctx));
                out.flush();
                out.close();
            }catch (Exception e){

            }
            return null;
        }
    }

    /**
     * token为空
     * @return
     */
    @ResponseBody
    public String getJsonTokenIsEmpty(RequestContext ctx){
        JSONObject jsonDate = new JSONObject();
        ctx.getResponse().setStatus(HttpServletResponse.SC_FORBIDDEN);
        ctx.getResponse().setContentType("text/html;charset=UTF-8");
        ctx.getResponse().setCharacterEncoding("UTF-8");
        jsonDate.put("status",ctx.getResponseStatusCode());
        jsonDate.put("msg","accessToken is empty!");
        return jsonDate.toString();
    }

    @ResponseBody
    public String getJsonTokenIsOk(RequestContext ctx,Claims claims){
        JSONObject jsonDate = new JSONObject();
        ctx.getResponse().setStatus(HttpServletResponse.SC_FORBIDDEN);
        ctx.getResponse().setContentType("text/html;charset=UTF-8");
        ctx.getResponse().setCharacterEncoding("UTF-8");
        jsonDate.put("status",ctx.getResponseStatusCode());
        jsonDate.put("msg","access token ok!");
        jsonDate.put("data",claims);
        return jsonDate.toString();
    }

}

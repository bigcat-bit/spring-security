/**
 * 
 */
package com.imooc.security;

import org.springframework.social.connect.Connection;
import org.springframework.social.connect.ConnectionSignUp;
import org.springframework.stereotype.Component;

/**
 * @author zhailiang
 * 在实现了QQ登录之后,自动帮用户注册,保存注册信息在数据库中
 */
@Component
public class DemoConnectionSignUp implements ConnectionSignUp {


	@Override
	public String execute(Connection<?> connection) {
		
		return connection.getDisplayName();
	}

}

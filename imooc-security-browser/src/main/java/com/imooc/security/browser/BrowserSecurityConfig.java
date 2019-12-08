/**
 * 
 */
package com.imooc.security.browser;

import java.util.Arrays;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.social.security.SpringSocialConfigurer;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.imooc.security.core.authentication.FormAuthenticationConfig;
import com.imooc.security.core.authentication.mobile.SmsCodeAuthenticationSecurityConfig;
import com.imooc.security.core.authorize.AuthorizeConfigManager;
import com.imooc.security.core.properties.SecurityProperties;
import com.imooc.security.core.validate.code.ValidateCodeSecurityConfig;

/**
 * 浏览器环境下安全配置主类
 * 
 * @author zhailiang
 *
 */
@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private SecurityProperties securityProperties;
	
	// 数据源在application.properties中已经配置了
	@Autowired
	private DataSource dataSource;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private SmsCodeAuthenticationSecurityConfig smsCodeAuthenticationSecurityConfig;
	
	@Autowired
	private ValidateCodeSecurityConfig validateCodeSecurityConfig;
	
	@Autowired
	private SpringSocialConfigurer imoocSocialSecurityConfig;
	
	@Autowired
	private SessionInformationExpiredStrategy sessionInformationExpiredStrategy;
	
	@Autowired
	private InvalidSessionStrategy invalidSessionStrategy;
	
	@Autowired
	private LogoutSuccessHandler logoutSuccessHandler;
	
	@Autowired
	private AuthorizeConfigManager authorizeConfigManager;
	
	@Autowired
	private FormAuthenticationConfig formAuthenticationConfig;
	
	
	@Override
	public void configure(WebSecurity web) throws Exception {
	        web.ignoring().antMatchers("/css/**");
	        web.ignoring().antMatchers("/js/**");
	        web.ignoring().antMatchers("/fonts/**");
	}
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		// 表单登录配置
		formAuthenticationConfig.configure(http);
		
		http.apply(validateCodeSecurityConfig)
				.and()
			.apply(smsCodeAuthenticationSecurityConfig)
				.and()
			.apply(imoocSocialSecurityConfig)
				.and()
			//记住我配置，如果想在'记住我'登录时记录日志，可以注册一个InteractiveAuthenticationSuccessEvent事件的监听器
			.rememberMe()
				.tokenRepository(persistentTokenRepository())
				.tokenValiditySeconds(securityProperties.getBrowser().getRememberMeSeconds())
				.userDetailsService(userDetailsService)
				.and()
			.authorizeRequests().antMatchers("**","/sdf","/2FA","333/FA").hasRole("admin")
			.anyRequest().authenticated()	
				.and()
			.sessionManagement()
				.invalidSessionStrategy(invalidSessionStrategy)
				.maximumSessions(securityProperties.getBrowser().getSession().getMaximumSessions())
				.maxSessionsPreventsLogin(securityProperties.getBrowser().getSession().isMaxSessionsPreventsLogin())
				.expiredSessionStrategy(sessionInformationExpiredStrategy)
				.and()
				.and()
				
			.logout()
				.logoutUrl("/signOut")
				.logoutSuccessHandler(logoutSuccessHandler)
				.deleteCookies("JSESSIONID")
				.and()
				.headers()
				.and().cors().
				// .antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')")      
				and()
			.csrf().disable();
		
		authorizeConfigManager.config(http.authorizeRequests());
	}

	/**
	 * 记住我功能的token存取器配置
	 * @return
	 */
	@Bean
	public PersistentTokenRepository persistentTokenRepository() {
		JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
		tokenRepository.setDataSource(dataSource);
		// 在JdbcTokenRepositoryImpl中有一个常亮CREATE_TABLE_SQL，就是用来创建表的sql，可以在数据库中执行这段sql
		// 也可以使用下面的方式创建，但是如果表已经存在了，下面的代码会报错
//		tokenRepository.setCreateTableOnStartup(true);
		return tokenRepository;
	}
	@Bean
	CorsConfigurationSource corsConfigurationSource() {
	    CorsConfiguration configuration = new CorsConfiguration();
	    
	    configuration.setAllowedOrigins(Arrays.asList("https://example.com"));
	    configuration.setAllowedMethods(Arrays.asList("GET","POST"));
	    configuration.addExposedHeader("Location"); // 暴露 Location header
	    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
	    source.registerCorsConfiguration("/**", configuration);
	    return source;
	}
}

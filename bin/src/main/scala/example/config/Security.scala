package example.config

import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.context.annotation.Bean

import java.util.ArrayList
import java.util.List

@Configuration
@EnableWebSecurity
class Security  @Autowired()(
    accessDeniedHandler :AccessDeniedHandler
  ) extends WebSecurityConfigurerAdapter {

    // roles admin allow to access /admin/**
    // roles user allow to access /user/**
    // custom 403 access denied handler
    @throws(classOf[Exception])
    override def configure(http :HttpSecurity): Unit = {
  		http
  			.authorizeRequests()
        .antMatchers("/user").access("hasRole('USER') or hasRole('SUPER')")
        .antMatchers("/admin").access("hasRole('ADMIN') or hasRole('SUPER')")
        .antMatchers("/super").access("hasRole('SUPER')")
  				.antMatchers("/login").permitAll()
  				.anyRequest().authenticated()
  				.and()
  			.formLogin()
  				.loginPage("/login")
          .loginProcessingUrl("/login")
          .successHandler(myAuthenticationSuccessHandler())
  				.permitAll()
    }

    @Bean
    def myAuthenticationSuccessHandler(): AuthenticationSuccessHandler = {
        return new MySimpleUrlAuthenticationSuccessHandler()
    }

    @Bean
  	def passwordEncoder(): PasswordEncoder =
  	{
  		try {
  			return new example.security.TripleDESPasswordEncoder()
  		} catch{
        case e :Exception => {}
      }
  		println("Using default.")
  		return new org.springframework.security.crypto.scrypt.SCryptPasswordEncoder()
  	}

    @Bean
    def inMemoryUserDetailsManager(): InMemoryUserDetailsManager = {
      return userDetailsService().asInstanceOf[InMemoryUserDetailsManager]
    }

  	override def userDetailsService(): UserDetailsService = {

      var userDetailsList = new ArrayList[UserDetails]()

      userDetailsList.add(
        User.withUsername("admin")
 				  .password(passwordEncoder().encode("pass"))
          .roles("ADMIN")
          .build()
      )

      userDetailsList.add(
        User.withUsername("user")
 				  .password(passwordEncoder().encode("pass"))
          .roles("USER")
          .build()
      )

      userDetailsList.add(
        User.withUsername("super")
 				  .password(passwordEncoder().encode("pass"))
          .roles("SUPER")
          .build()
      )

      return new InMemoryUserDetailsManager(userDetailsList)
  	}

    @throws(classOf[Exception])
    @Bean
    override def authenticationManagerBean() : AuthenticationManager = {
        return super.authenticationManagerBean();
    }

}

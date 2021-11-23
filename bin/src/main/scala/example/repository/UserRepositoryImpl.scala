package example.repository;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.{ArrayList, List};

@Repository
class UserRepositoryImpl @Autowired()(
    inMemoryUserDetailsManager :InMemoryUserDetailsManager
    , passwordEncoder :PasswordEncoder
  ) extends UserRepository {

    override def findUserByName(name :String): UserDetails = {
        return inMemoryUserDetailsManager.loadUserByUsername(name);
    }

    override def save(user :example.model.User): Unit = {
      val name :String = user.username;
      val password :String = user.password;

      var grantedAuthoritiesList :List[GrantedAuthority] = new ArrayList()
      grantedAuthoritiesList.add(new SimpleGrantedAuthority("ROLE_USER"));

      inMemoryUserDetailsManager
      .createUser(new org.springframework.security.core.userdetails.User(name, passwordEncoder.encode(password), grantedAuthoritiesList));

    }
}

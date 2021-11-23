package example.repository;

import example.model.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

@Repository("userRepository")
trait UserRepository {
    def findUserByName(name :String) : UserDetails;
    def save(user :User);
}

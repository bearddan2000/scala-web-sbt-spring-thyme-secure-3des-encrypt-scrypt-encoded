package example.service;

import example.model.User;
import example.repository.UserRepository;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
class UserServiceImpl @Autowired()(
    userRepository :UserRepository
  ) extends UserService {

  override def save(user :User): Unit = {
        user.role = "ROLE_USER";
        userRepository.save(user);
        println("[LOG] user saved");
    }

    override def findByUsername(username :String): UserDetails = {
        return userRepository.findUserByName(username);
    }
}

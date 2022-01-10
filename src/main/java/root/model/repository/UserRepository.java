package root.model.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import root.model.entity.UserEntity;

public interface UserRepository extends JpaRepository <UserEntity, Integer> {
    @Query("select u from UserEntity u where u.login = ?1")
    public UserEntity findUserByLogin(String login);
}

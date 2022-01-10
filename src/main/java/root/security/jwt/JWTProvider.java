package root.security.jwt;

public interface JWTProvider {
    public String generateJWT(String login);

    public boolean validateJWT(String token);

    String getLoginFromJWT(String token);
}

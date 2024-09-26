
## 1. SecurityConfig 기본 요소 작성
- postman 을 이용해 로그인 테스트를 진행
  - form login 방식을 disable 시킨다.
  - 헤더 방식 인증(httpBasic) disable
  - 경로별 인가 작업
  - jwt 인증을 위한 세션 stateless 설정

## 2. 회원가입
- username, password 정보를 담고있는 User entity 생성
- JoinController 를 통해 DB 에 회원정보 저장

## 3. 로그인 필터로 로그인 정보 추출
- 스프링 시큐리티 필터 사용
- 폼 로그인 기능이 켜져있었다면 스프링 시큐리티가 내부적으로 UsernamePasswordAuthenticationFilter 를 이용해 username 과 password 를 검증했겠지만, 폼 로그인 기능을 꺼둔 상태이므로 이 부분을 직접 구현해야 한다.
- UsernamePasswordAuthenticationFilter 를 상속받은 [LoginFilter](https://github.com/zhtmr/springJwt-ex/blob/677c25ae9b9ee6fbb6a6e83431799fcd80afff79/src/main/java/com/ex/springjwtex/jwt/LoginFilter.java) 구현
- 스프링 시큐리티는 request 정보에서 username 과 password 라는 키값으로 정보를 가져온 뒤 유효성 검증을 진행한다.
  ![img.png](img.png)    
    
  ![img_1.png](img_1.png)
- 위 사진은 form login 방식을 이용했을 때 실행되는 메소드다. 유효성 검증이 끝난 username 과 password 를 UsernamePasswordAuthenticationToken 에 담아 authenticationManager 로 보내는 것을 알 수 있다. 우리가 구현해야 할 부분이 이 부분이다. 
- 스프링 시큐리티의 구현 방식을 따라 username 과 password 를 UsernamePasswordAuthenticationToken 에 담아 전달해준다.
  ```java
  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
  HttpServletResponse response) throws AuthenticationException {
    
  //클라이언트 요청에서 username, password 추출
  String username = obtainUsername(request);
  String password = obtainPassword(request);
    
  System.out.println("username = " + username);
    
  //스프링 시큐리티에서 username과 password를 검증하기 위해서는 token에 담아야 함
  UsernamePasswordAuthenticationToken authToken =
  new UsernamePasswordAuthenticationToken(username, password, null);
    
  //token 에 담아 AuthenticationManager로 전달
  return authenticationManager.authenticate(authToken);
    
  }
  ```
- 이 LoginFilter 를 스프링 시큐리티에 등록해 준다. 스프링 시큐리티는 api 요청을 가로채 이 필터를 먼저 실행하게 된다.
  ```java
  // SecurityConfig
  // 필터 추가 LoginFilter()는 인자를 받음 (AuthenticationManager() 메소드에 authenticationConfiguration 객체를 넣어야 함) 따라서 등록 필요
  http
    .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);
  ```
- 여기까지 로그인 인증 작업이 완료되었다. 이제 이 유저 정보를 이용해 DB 데이터와 비교하고([4](#4-db-유저-정보-검증)), 일치하면 JWT 토큰을 발급해서 클라이언트에게 보내줘야 한다.([5](#5-jwt-발급-클래스-작성)) 그후 클라이언트가 이 토큰을 이용해 접근할 수 있도록 또 다른 필터(JWTFilter)를 등록하는 작업을 진행해야 한다.([6](#6. ))

## 4. DB 유저 정보 검증

![img_3.png](img_3.png)*출처: https://goldenrabbit.co.kr/2024/04/05/spring-%EC%8A%A4%ED%94%84%EB%A7%81-%EC%8B%9C%ED%81%90%EB%A6%AC%ED%8B%B0%EB%9E%80/*

스프링 시큐리티는 사용자 정보를 가져오는데 UserDetailService 를 사용한다. 이 클래스를 상속 받은 뒤 loadUserByUsername() 을 오버라이드하면 스프링 시큐리티에서 오버라이드된 메서드를 사용하게 된다.
```java
@Service
public class CustomUserDetailsService implements UserDetailsService {
  private final UserRepository userRepository;

  public CustomUserDetailsService(UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsername(username);
    if (user != null) {
      //UserDetails에 담아서 return하면 AuthenticationManager 검증 함
      return new CustomUserDetails(user);
    }
    return null;
  }
}
```

UserDetailsService 는 사용자 정보를 UserDetail 객체에 담아서 AuthenticationManager 에 전달하도록 구성해야 한다. 이를 위해 UserDetails 를 오버라이드 한 [CustomUserDetails](https://github.com/zhtmr/springJwt-ex/blob/c84845a1161854ead757761ff31ee5d58460f49d/src/main/java/com/ex/springjwtex/dto/CustomUserDetails.java) 를 만든다.

UserDetails 를 구현하면 각종 유저 정보에 대한 메서드를 오버라이딩 해야한다. 즉, 이 UserDetails 을 구현한 클래스에서 DB 에서 조회한 유저 정보를 갖고 있게 된다. 스프링 시큐리티 흐름 내에서 인증된 유저의 정보를 꺼내고 싶으면 이 UserDetails 객체에서 정보를 꺼내면 된다.


## 5. JWT 발급 클래스 작성
### jwt 구조
먼저 jwt 의 구조와 개념에 대해서 알아보자.
jwt 는 header / payload / signature 구조로 이루어져 있다.

![img_2.png](img_2.png)

- Header
  - jwt 임을 명시
  - 사용된 암호화 알고리즘
- Payload
  - 정보
- Signature
  - Base64(header) + Base64(payload) + secret key

jwt 는 입장권이라고 생각하면 된다. 
간단한 정보와 서명이 적혀 있고 이를 서버에 제시하면 서버에서 검증 후 통과 여부를 판단한다.
payload 에는 username 이나 role 처럼 외부에서 열람해도 상관없는 정보를 담아야 하며, 비밀번호 같은 정보는 절대 담아선 안된다. 애초에 그런 정보를 담을 필요가 없다.
서버에서 jwt 를 생성했을 때의 값과 클라이언트에서 보내오는 jwt 정보가 같은지에 대해서만 비교하기 때문이다.

만약 발급된 토큰을 탈취당해 payload 값이 바뀐다면 signature 값도 바뀌므로 서버 인증 실패할 것이다. 그러나 secret key 값이 너무 짧거나 유추하기 쉽다면 brute force 에 의해 뚫릴 수 있다. 이를 방지하기 위해선 서버에서 정의한 secret key 값이 충분히 길고 복잡해야 한다.

### jwt 발급 클래스
![img_4.png](img_4.png)

지금까지 작업한 내용으로 서버를 구동시키고 postman 으로 회원가입과 로그인 요청을 보내면 정상적으로 작동한다.
그러나 `/admin` 과 같이 인가(Authorization)가 필요한 경로에 대해선 거부될 것이다. 
SecurityConfig 에 해당 경로에 대해선 ADMIN 권한이 있는 사용자만 접근 가능하도록 설정했기 때문이다.

ADMIN 권한을 가진 사용자가 해당 api 를 사용하도록 하려면 요청 시 제시한 입장권(jwt)에서 권한정보를 가져와 확인하는 작업을 해야한다. 이 작업을 할 클래스와 필터를 정의한다.

#### secret key 설정
jwt 발급을 담당할 클래스를 작성하기 전에 secret key 를 애플리케이션 내부에서 관리하고 있어야 한다.
```properties
# application.properties
spring.jwt.secret=vmfhaltmskdlstkfkdgodyroqkfwkdbalroqkfwkdbalaaaaaagregaaaaaaaabbbbb
```
#### jwt 의존성 추가
jwt 의존성을 추가한다.
```groovy
// build.gradle
implementation 'io.jsonwebtoken:jjwt-api:0.12.3'
implementation 'io.jsonwebtoken:jjwt-impl:0.12.3'
implementation 'io.jsonwebtoken:jjwt-jackson:0.12.3'
```
적당히 길고 복잡한 문자열을 application.properties 에 작성해 둔다.

[JWTUtil](https://github.com/zhtmr/springJwt-ex/blob/1fe7a4c86eb4a6e04cd9c6ab3cdfa1a3f8f80ca3/src/main/java/com/ex/springjwtex/jwt/JWTUtil.java) 클래스에서 application.properties 에 정의한 secret key 값을 가져와 객체 형태로 만든다.
이 secret key 값은 위 jwt 구조에서 봤듯이 signature 를 만드는데 사용된다.

#### jwt 토큰 검증 및 생성 메소드
요청시 보내온 jwt 값에서 username 과 role 값을 추출하기 위한 메소드를 생성한다.
```java
public String getUsername(String token) {
    return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
  }

public String getRole(String token) {
  return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
}
```
token 파라미터 값으로 jwt 가 전달될 것이다. secret key 로 signature 검증 후 payload 값을 추출한다.

그리고 jwt 토큰은 만료시간 설정이 필요한데, 토큰이 만료되었는지 아닌지를 확인할 메서드도 만든다.
```java
public Boolean isExpired(String token) {
  return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
}
```

jwt 토큰을 생성을 위한 메소드
```java
public String createJwt(String username, String role, Long expiredMs) {
  return Jwts.builder()
      .claim("username", username)
      .claim("role", role)
      .issuedAt(new Date(System.currentTimeMillis()))
      .expiration(new Date(System.currentTimeMillis() + expiredMs))
      .signWith(secretKey)
      .compact();
}
```
## 6.


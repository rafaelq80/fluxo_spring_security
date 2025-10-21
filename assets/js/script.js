// Dados dos fluxos
const flowsData = {
    login: {
        title: "Fluxo 1: Login e Geração do Token",
        icon: `<circle cx="12" cy="12" r="10"></circle><path d="M12 16v-4"></path><path d="M12 8h.01"></path>`,
        summary: "O processo de login valida as credenciais do usuário no banco de dados e, se corretas, gera um token JWT assinado que será usado nas próximas requisições.",
        steps: [
            {
                number: 1,
                title: "Usuário envia credenciais",
                description: "O cliente faz uma requisição POST para /usuarios/logar com email e senha no corpo da requisição.",
                color: "blue",
                icon: `<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle>`,
                code: `POST /usuarios/logar
Body: {
  "usuario": "maria@email.com",
  "senha": "senha123"
}`
            },
            {
                number: 2,
                title: "SecurityConfig permite acesso",
                description: "O endpoint /usuarios/logar está na lista PUBLIC_ENDPOINTS, então o Spring Security permite o acesso sem necessidade de autenticação.",
                color: "green",
                icon: `<rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path>`,
                code: `// SecurityConfig.java
private static final String[] PUBLIC_ENDPOINTS = {
    "/usuarios/logar",
    "/usuarios/cadastrar",
    // ...
};
.requestMatchers(PUBLIC_ENDPOINTS).permitAll()`
            },
            {
                number: 3,
                title: "Controller recebe requisição",
                description: "O controller de usuários recebe as credenciais e utiliza o AuthenticationManager para validar email e senha.",
                color: "purple",
                icon: `<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline>`,
                code: `// UsuarioController.java
@PostMapping("/logar")
public ResponseEntity<UsuarioLogin> autenticar(
    @RequestBody Optional<UsuarioLogin> usuarioLogin) {
    
    // Autentica as credenciais
    return usuarioService.autenticarUsuario(usuarioLogin)
        .map(resp -> ResponseEntity.status(200).body(resp))
        .orElse(ResponseEntity.status(401).build());
}`
            },
            {
                number: 4,
                title: "UserDetailsService busca usuário",
                description: "O Spring Security chama o UserDetailsServiceImpl para buscar o usuário no banco de dados pelo email fornecido.",
                color: "blue",
                icon: `<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle>`,
                code: `// UserDetailsServiceImpl.java
@Override
public UserDetails loadUserByUsername(String username) {
    Optional<Usuario> usuario = 
        usuarioRepository.findByUsuario(username);
    
    if (usuario.isPresent()) {
        return new UserDetailsImpl(usuario.get());
    } else {
        throw new UsernameNotFoundException(
            "Usuário não encontrado: " + username);
    }
}`
            },
            {
                number: 5,
                title: "Validação da senha",
                description: "O Spring Security compara a senha fornecida (após criptografia BCrypt) com a senha armazenada no banco de dados.",
                color: "orange",
                icon: `<rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path>`,
                code: `// Internamente o Spring Security faz:
boolean senhaCorreta = passwordEncoder.matches(
    senhaFornecida,    // "senha123"
    senhaArmazenada    // "$2a$10$hash..."
);`
            },
            {
                number: 6,
                title: "JwtService gera o token",
                description: "Se a autenticação for bem-sucedida, o JwtService gera um token JWT assinado com a chave secreta, contendo o email do usuário e tempo de expiração de 60 minutos.",
                color: "green",
                icon: `<circle cx="12" cy="12" r="10"></circle><path d="M12 16v-4"></path><path d="M12 8h.01"></path>`,
                code: `// JwtService.java
public String generateToken(String username) {
    Instant now = Instant.now();
    return Jwts.builder()
        .subject(username)  // email do usuário
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plus(EXPIRATION_DURATION)))
        .signWith(signingKey)  // assina com chave secreta
        .compact();
}`
            },
            {
                number: 7,
                title: "Token é retornado ao cliente",
                description: "O servidor retorna status 200 com o token JWT no corpo da resposta. O cliente deve armazenar este token (geralmente no localStorage) para usar nas próximas requisições.",
                color: "green",
                icon: `<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>`,
                code: `Response 200 OK
Body: {
  "id": 1,
  "nome": "Maria Silva",
  "usuario": "maria@email.com",
  "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJtYXJpYUBl..."
}`
            }
        ]
    },
    protected: {
        title: "Fluxo 2: Acesso a Endpoint Protegido (com token válido)",
        icon: `<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>`,
        summary: "Quando o cliente envia um token válido, o JwtAuthFilter valida o token, carrega os dados do usuário e registra a autenticação no SecurityContext, liberando o acesso ao endpoint protegido.",
        steps: [
            {
                number: 1,
                title: "Cliente envia requisição com token",
                description: "O cliente faz uma requisição para um endpoint protegido (ex: /postagens) incluindo o token JWT no header Authorization com o prefixo 'Bearer '.",
                color: "blue",
                icon: `<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle>`,
                code: `GET /postagens HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIi...`
            },
            {
                number: 2,
                title: "JwtAuthFilter intercepta a requisição",
                description: "O JwtAuthFilter é executado ANTES de qualquer controller. Ele extrai o token do header Authorization removendo o prefixo 'Bearer '.",
                color: "purple",
                icon: `<rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path>`,
                code: `// JwtAuthFilter.java
private String extractTokenFromRequest(HttpServletRequest request) {
    String authHeader = request.getHeader("Authorization");
    
    if (authHeader != null && 
        authHeader.startsWith("Bearer ") && 
        authHeader.length() > 7) {
        return authHeader.substring(7);  // Remove "Bearer "
    }
    return null;
}`
            },
            {
                number: 3,
                title: "JwtService extrai o username do token",
                description: "O JwtService decodifica o token JWT usando a chave secreta e extrai o subject (email do usuário) que foi armazenado no momento da criação do token.",
                color: "orange",
                icon: `<circle cx="12" cy="12" r="10"></circle><path d="M12 16v-4"></path><path d="M12 8h.01"></path>`,
                code: `// JwtService.java
public String extractUsername(String token) {
    return extractAllClaims(token).getSubject();
}
private Claims extractAllClaims(String token) {
    return Jwts.parser()
        .verifyWith(signingKey)  // valida assinatura
        .build()
        .parseSignedClaims(token)
        .getPayload();
}`
            },
            {
                number: 4,
                title: "UserDetailsService carrega dados do usuário",
                description: "Com o email extraído do token, o sistema busca os dados completos do usuário no banco de dados através do UserDetailsServiceImpl.",
                color: "blue",
                icon: `<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle>`,
                code: `// JwtAuthFilter.java
String username = jwtService.extractUsername(token);
UserDetails userDetails = 
    userDetailsService.loadUserByUsername(username);
// Retorna UserDetailsImpl com dados do banco`
            },
            {
                number: 5,
                title: "JwtService valida o token",
                description: "O JwtService verifica se o token é válido comparando o username do token com o username do banco de dados, e checando se o token não expirou (ainda está dentro das 60 minutos).",
                color: "orange",
                icon: `<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>`,
                code: `// JwtService.java
public boolean validateToken(String token, UserDetails userDetails) {
    Claims claims = extractAllClaims(token);
    return claims.getSubject().equals(userDetails.getUsername()) && 
           claims.getExpiration().after(new Date());
}`
            },
            {
                number: 6,
                title: "Autenticação é registrada no SecurityContext",
                description: "Se o token for válido, o JwtAuthFilter cria um objeto de autenticação e o registra no SecurityContext do Spring Security, indicando que o usuário está autenticado para esta requisição.",
                color: "green",
                icon: `<rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path>`,
                code: `// JwtAuthFilter.java
UsernamePasswordAuthenticationToken authToken = 
    new UsernamePasswordAuthenticationToken(
        userDetails, 
        null, 
        userDetails.getAuthorities()
    );
authToken.setDetails(
    new WebAuthenticationDetailsSource().buildDetails(request)
);
SecurityContextHolder.getContext().setAuthentication(authToken);`
            },
            {
                number: 7,
                title: "Requisição segue para o controller",
                description: "Com o usuário autenticado no SecurityContext, a requisição é liberada para seguir até o controller. O Spring Security permite o acesso ao endpoint protegido e o controller processa normalmente.",
                color: "green",
                icon: `<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>`,
                code: `// Controller recebe a requisição normalmente
@GetMapping
public ResponseEntity<List<Produto>> getAll() {
    return ResponseEntity.ok(produtoRepository.findAll());
}
// Response 200 OK com a lista de postagens`
            }
        ]
    },
    noToken: {
        title: "Fluxo 3: Tentativa de Acesso SEM Token",
        icon: `<circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line>`,
        summary: "Quando não há token na requisição, o Spring Security detecta que o endpoint requer autenticação e o AuthenticationEntryPoint retorna status 401, informando que é necessário se autenticar.",
        steps: [
            {
                number: 1,
                title: "Cliente envia requisição SEM token",
                description: "O cliente tenta acessar um endpoint protegido (ex: /postagens) mas não inclui o token JWT no header Authorization.",
                color: "blue",
                icon: `<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle>`,
                code: `GET /postagens HTTP/1.1
// Sem header Authorization`
            },
            {
                number: 2,
                title: "JwtAuthFilter não encontra token",
                description: "O JwtAuthFilter verifica o header Authorization, não encontra nenhum token, e permite que a requisição continue sem definir autenticação no SecurityContext.",
                color: "orange",
                icon: `<rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path>`,
                code: `// JwtAuthFilter.java
String token = extractTokenFromRequest(request);
if (token == null || 
    SecurityContextHolder.getContext().getAuthentication() != null) {
    filterChain.doFilter(request, response);
    return;  // Não há autenticação definida
}`
            },
            {
                number: 3,
                title: "SecurityConfig verifica autorização",
                description: "A requisição chega ao SecurityConfig que verifica se o endpoint /postagens requer autenticação. Como está configurado com .anyRequest().authenticated(), o acesso é negado.",
                color: "red",
                icon: `<rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path>`,
                code: `// SecurityConfig.java
.authorizeHttpRequests(auth -> auth
    .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
    .anyRequest().authenticated()  // /postagens requer autenticação
)`
            },
            {
                number: 4,
                title: "AuthenticationEntryPoint retorna 401",
                description: "Como não há autenticação no SecurityContext, o Spring Security lança uma exceção de autenticação. O AuthenticationEntryPoint configurado intercepta essa exceção e retorna status 401 Unauthorized ao cliente.",
                color: "red",
                icon: `<circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line>`,
                code: `// SecurityConfig.java
.exceptionHandling(exceptions -> exceptions
    .authenticationEntryPoint((request, response, authException) -> 
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, 
            "Não autorizado - Token JWT ausente ou inválido")
    )
)
// Response: 401 Unauthorized`
            }
        ]
    },
    invalid: {
        title: "Fluxo 4: Tentativa de Acesso com Token Inválido/Expirado",
        icon: `<circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line>`,
        summary: "Quando o token está expirado, tem assinatura inválida ou está malformado, o JwtService lança uma exceção que é capturada pelo JwtAuthFilter, retornando status 401 e bloqueando o acesso.",
        steps: [
            {
                number: 1,
                title: "Cliente envia token inválido/expirado",
                description: "O cliente faz uma requisição incluindo um token JWT que está expirado (mais de 60 minutos), tem assinatura inválida, ou está malformado.",
                color: "blue",
                icon: `<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle>`,
                code: `GET /postagens HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.INVALID_TOKEN...`
            },
            {
                number: 2,
                title: "JwtAuthFilter extrai o token",
                description: "O JwtAuthFilter extrai o token do header Authorization normalmente e tenta processá-lo.",
                color: "purple",
                icon: `<rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path>`,
                code: `// JwtAuthFilter.java
String token = extractTokenFromRequest(request);
if (token == null || 
    SecurityContextHolder.getContext().getAuthentication() != null) {
    filterChain.doFilter(request, response);
    return;
}
processJwtAuthentication(request, token);  // Tenta processar`
            },
            {
                number: 3,
                title: "JwtService lança exceção ao validar",
                description: "Ao tentar extrair dados ou validar o token, o JwtService lança uma exceção (ExpiredJwtException para token expirado, SignatureException para assinatura inválida, ou MalformedJwtException para token malformado).",
                color: "red",
                icon: `<circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line>`,
                code: `// JwtService.java
private Claims extractAllClaims(String token) {
    return Jwts.parser()
        .verifyWith(signingKey)
        .build()
        .parseSignedClaims(token)  // Lança exceção aqui
        .getPayload();
}
// Possíveis exceções:
// - ExpiredJwtException: token expirado
// - SignatureException: assinatura inválida
// - MalformedJwtException: formato inválido`
            },
            {
                number: 4,
                title: "JwtAuthFilter captura exceção",
                description: "O bloco try-catch do JwtAuthFilter captura as exceções de token inválido e define o status HTTP 401 Unauthorized na resposta, impedindo que a requisição continue.",
                color: "red",
                icon: `<rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path>`,
                code: `// JwtAuthFilter.java
try {
    String token = extractTokenFromRequest(request);
    // ... processamento
    filterChain.doFilter(request, response);
    
} catch (ExpiredJwtException | SignatureException | 
         MalformedJwtException | UsernameNotFoundException e) {
    response.setStatus(HttpStatus.UNAUTHORIZED.value());
}
// Response: 401 Unauthorized`
            }
        ]
    }
};

// Estado atual
let currentFlow = 'login';

// Função para criar ícone SVG
function createIcon(pathData) {
    return `<svg class="icon-small" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${pathData}</svg>`;
}

// Função para renderizar um step
function renderStep(step) {
    return `
        <div class="flow-step ${step.color}">
            <div class="step-content">
                <div class="step-number ${step.color}">${step.number}</div>
                <div class="step-body">
                    <div class="step-header">
                        ${createIcon(step.icon)}
                        <h3 class="step-title">${step.title}</h3>
                    </div>
                    <p class="step-description">${step.description}</p>
                    ${step.code ? `
                        <button class="toggle-code-btn" onclick="toggleCode(this)">
                            <svg class="icon-small chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="6 9 12 15 18 9"></polyline>
                            </svg>
                            Ver código envolvido
                        </button>
                        <pre class="code-block"><code>${step.code}</code></pre>
                    ` : ''}
                </div>
            </div>
        </div>
    `;
}

// Função para alternar visibilidade do código
function toggleCode(button) {
    const codeBlock = button.nextElementSibling;
    const chevron = button.querySelector('.chevron');
    const isVisible = codeBlock.classList.contains('visible');
    
    if (isVisible) {
        codeBlock.classList.remove('visible');
        chevron.innerHTML = '<polyline points="6 9 12 15 18 9"></polyline>';
        button.childNodes[2].textContent = 'Ver código envolvido';
    } else {
        codeBlock.classList.add('visible');
        chevron.innerHTML = '<polyline points="18 15 12 9 6 15"></polyline>';
        button.childNodes[2].textContent = 'Ocultar código envolvido';
    }
}

// Função para renderizar o fluxo atual
function renderFlow() {
    const flow = flowsData[currentFlow];
    const stepsContainer = document.getElementById('stepsContainer');
    const summaryText = document.getElementById('summaryText');
    const flowTitle = document.querySelector('.flow-title');
    const flowIcon = document.querySelector('.current-flow-icon');
    
    // Atualizar título e ícone
    flowTitle.textContent = flow.title;
    flowIcon.innerHTML = flow.icon;
    
    // Renderizar steps
    stepsContainer.innerHTML = flow.steps.map(step => renderStep(step)).join('');
    
    // Atualizar resumo
    summaryText.textContent = flow.summary;
}

// Função para trocar de fluxo
function switchFlow(flowKey) {
    currentFlow = flowKey;
    
    // Atualizar botões ativos
    document.querySelectorAll('.flow-btn').forEach(btn => {
        if (btn.dataset.flow === flowKey) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });
    
    // Renderizar novo fluxo
    renderFlow();
    
    // Scroll suave para o topo do conteúdo
    document.querySelector('.content-card').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Inicialização
document.addEventListener('DOMContentLoaded', () => {
    // Adicionar event listeners aos botões de fluxo
    document.querySelectorAll('.flow-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            switchFlow(btn.dataset.flow);
        });
    });
    
    // Renderizar fluxo inicial
    renderFlow();
});

// Expor função toggleCode globalmente
window.toggleCode = toggleCode;
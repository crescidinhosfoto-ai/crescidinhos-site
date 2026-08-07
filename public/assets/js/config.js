// CONFIGURAÇÃO CENTRAL — único arquivo que Thais edita
// Datas, preços, contatos e conteúdo dinâmico

const CONFIG = {
  // MARCA
  estudio: {
    nome: "Crescidinhos Fotografia",
    marca: "crescidinhos",
    descricao: "Ensaios infantis atípicos, sem crises, com método",
  },

  curso: {
    nome: "O Fantástico Mundo de B.O.B.",
    marca: "bob",
    descricao: "Curso para fotógrafas: Brincar · Ouvir · Brilhar",
  },

  // CONTATOS
  contatos: {
    whatsapp_studio: "5514996845521", // Clarice
    whatsapp_curso: "14988404870",    // Betina
    instagram_studio: "thaisdesafotografia",
    instagram_curso: "fantastico.mundo.de.bob",
    email: "crescidinhosfoto@gmail.com",
  },

  // DATAS — lançamentos e prazos
  datas: {
    bob_lancamento: "2026-09-09",
    bob_carrinho_fecha: "2026-09-16",
    natal_lote1_abre: "2026-09-21",
    natal_lote1_fecha: "2026-10-21",
    natal_lote2_abre: "2026-10-22",
    natal_lote2_fecha: "2026-11-22",
    natal_lote3_abre: "2026-11-23",
    natal_lote3_fecha: "2026-12-21",
  },

  // PREÇOS
  precos: {
    // B.O.B. — curso
    bob_cheio: 697,
    bob_lista_quero: 497,
    bob_desconto_validade: 48,

    // E-books
    guia_sobrevivencia: 29.90,
    fotografia_terapeutica: 29.90,

    // Natal — 3 lotes
    natal_lote1: 297,
    natal_lote2: 367,
    natal_lote3: 447,
  },

  // CATÁLOGO DE PRODUTOS
  produtos: {
    curso_bob: {
      nome: "O Fantástico Mundo de B.O.B.",
      descricao: "Curso para fotógrafas: Brincar · Ouvir · Brilhar",
      preco_cheio: 697,
      preco_quero: 497,
      link_hotmart: "https://app.hotmart.com/",
      categoria: "aluno",
    },
  },

  // NATAL
  natal: {
    total_vagas: 80,
    vagas_por_dia: 8,
    duracao_sessao: "20-30 min",
    lotes: [
      { numero: 1, abre: "2026-09-21", fecha: "2026-10-21", preco: 297, vagas: 24 },
      { numero: 2, abre: "2026-10-22", fecha: "2026-11-22", preco: 367, vagas: 24 },
      { numero: 3, abre: "2026-11-23", fecha: "2026-12-21", preco: 447, vagas: 32 },
    ],
  },

  // ENDEREÇO
  endereco: {
    logradouro: "Padre Anchieta, 775",
    bairro: "Bela Vista",
    cidade: "Bauru",
    estado: "SP",
    cep: "17040-600",
  },
};

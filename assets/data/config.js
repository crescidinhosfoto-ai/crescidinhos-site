/* ==========================================================================
   CONFIG — datas, preços e links do site
   --------------------------------------------------------------------------
   Thais: este é o ÚNICO arquivo que você precisa editar quando um preço ou
   uma data mudar. Nada disso está escrito dentro do HTML.

   Existe um go/no-go em 01/09: se a lista QUERO tiver menos de 50 pessoas,
   o lançamento adia para novembro. Se isso acontecer, troque só as datas do
   bloco CURSO aqui embaixo — o site inteiro se ajusta sozinho.
   ========================================================================== */

window.CRESCI = {

  /* ---------------------------------------------------------------- CURSO */
  curso: {
    nome: 'O Fantástico Mundo de B.O.B.',

    // Carrinho 1
    abre:  '2026-09-09T09:00:00-03:00',
    fecha: '2026-09-16T23:59:59-03:00',

    precoCheio:  697,
    precoLista:  497,   // condição QUERO — só nas primeiras 48h do carrinho
    horasCondicao: 48,
    parcelas: 12,

    // Preencher quando a Hotmart estiver configurada
    checkout: '',       // ex.: 'https://pay.hotmart.com/XXXXXXX'
    areaAluno: '',

    garantiaDias: 7,    // obrigatório pelo CDC em compra online
  },

  /* ---------------------------------------------------------------- NATAL */
  natal: {
    sinalPercent: 40,
    vagasPorDia: 8,
    duracaoMin: '20 a 30 minutos',
    lotes: [
      { n: 1, de: '2026-09-21', ate: '2026-10-21', preco: 297, vagas: 24 },
      { n: 2, de: '2026-10-22', ate: '2026-11-22', preco: 367, vagas: 24 },
      { n: 3, de: '2026-11-23', ate: '2026-12-21', preco: 447, vagas: 32 },
    ],
    entregaLote3: '22/12',
  },

  /* -------------------------------------------------------------- CONTATO */
  contato: {
    email: 'crescidinhosfoto@gmail.com',
    whatsappEstudio: '5514996845521',        // Clarice — só estúdio
    whatsappCurso: '',                        // Betina — chip novo, a definir
    instagram: 'thaisdesafotografia',         // ✅ confirmado pela Thais em 03/08/2026
    cidade: 'Bauru/SP',
    agendamento: 'https://app.crescidinhosfoto.com.br',
  },

  /* ----------------------------------------------------------------- DADO */
  /* Fonte da estatística usada na página de vendas.
     IBGE, Censo Demográfico 2022 (divulgado em maio/2025).
     NÃO usar "1 em cada 36" — é número antigo do CDC e é dado dos EUA. */
  dado: {
    totalBrasil: '2,4 milhões',
    percentPopulacao: '1,2%',
    percent5a9: '2,6%',
    fonte: 'IBGE, Censo 2022',
  },
};

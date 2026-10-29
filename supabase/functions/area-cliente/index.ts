// =============================================================
// area-cliente — tranca da Área do Cliente, do lado do servidor.
//
// Por que existe: o app guardava o PIN no localStorage do celular, em
// texto puro, e conferia no navegador. O Safari do iPhone apaga esse
// armazenamento depois de ~7 dias sem uso, e a mãe perdia o acesso.
// Pior: a conferência varria a tabela inteira atrás do PIN digitado,
// sem amarrar à pessoa — dois PINs iguais abriam a conta errada.
//
// Aqui o PIN mora em `acesso_cliente`, que não tem policy nenhuma:
// só o service_role desta função alcança. O navegador nunca vê o hash.
//
// v18 (29/10/2026): FALHAS NO LOG. A Ilda não conseguia trocar a senha
//   e o banco estava limpo: identificador que não bate com o cadastro e
//   código que não chega não deixavam rastro nenhum (o código até era
//   apagado). Agora `acesso_cliente_log` registra: identificador_falhou
//   (nao_encontrada / ambiguo / telefone_incompleto — com o dado
//   mascarado e cliente_id nulo), envio_codigo_falhou, codigo_falhou e
//   pin_bloqueado.
//
// v17 (14/10/2026): ensaio com DUAS galerias não esconde mais as fotos.
//   A Luciana Galhardo não conseguia ver nem escolher as 162 fotos do
//   Natal dela: o ensaio tinha duas galerias (uma vazia e desligada), e
//   `.maybeSingle()` dá erro com mais de uma linha. O erro era
//   descartado e a resposta saía "galeria: null".
//
// v8 (22/09/2026): o CÓDIGO sai pela API oficial do WhatsApp (Meta),
//   pela WAME, com o modelo aprovado `codigo_acesso`. A Evolution, na
//   Cloudfy, dormia até 49s e caiu de vez em 21/09 — e com ela nenhuma
//   mãe sem PIN conseguia entrar. A reserva pela Evolution saiu em
//   22/09 (Cloudfy cancelada).
//
// v5 (16/09/2026): GALERIA. `minhas-fotos` e `escolher-fotos`, para a
//   cliente ver e escolher as fotos do ensaio dela. Desde 31/07 isso
//   estava QUEBRADO no app antigo: `galerias` só tem policy para a
//   fotógrafa, então a cliente não lia nem gravava — e a tela não
//   avisava. As galerias de 19/08 têm zero escolhas por causa disso.
//
// v4 (16/09/2026): SESSÃO. Acertar o PIN devolve um `token`, e a Área do
//   Cliente do app novo lê e grava por ele — `meus-dados`,
//   `atualizar-perfil`, `sair`. Nada mudou para o app antigo.
//
// v3 (10/09/2026): `criar-pin` não cria mais PIN sem código — o primeiro
//   PIN também nasce por `enviar-codigo` + `redefinir-pin`.
//
// v2 (10/09/2026): identificação por E-MAIL OU CELULAR e "esqueci a
//   senha" com código no WhatsApp do cadastro.
// =============================================================
import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const MAX_TENTATIVAS = 5;      // erros seguidos de PIN antes de trancar
const BLOQUEIO_MINUTOS = 15;
const ITERACOES = 210_000;     // PBKDF2

const CODIGO_VALIDADE_MIN = 10;
const CODIGO_MAX_TENTATIVAS = 5;
const CODIGOS_POR_HORA = 3;    // por cliente — segura quem aperta sem parar

// A WAME é um serviço hospedado, não dorme. 20s é folga.
const WAME_URL = (Deno.env.get("WAME_URL") ?? "https://us.api-wa.me").replace(/\/+$/, "");
const PRAZO_WAME_MS = 20_000;

const SESSAO_DIAS = 30;        // quanto tempo o celular continua entrando sozinho
const MAX_FOTOS_ESCOLHIDAS = 500;

const responder = (corpo: unknown, status = 200) =>
  new Response(JSON.stringify(corpo), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });

const soDigitos = (v: unknown) => String(v ?? "").replace(/\D/g, "");
const ehUuid = (v: unknown) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(v ?? ""));

// O cadastro tem telefone gravado de vários jeitos: com máscara, com o
// 55 na frente, com o 0 da ligação interurbana, com e sem o nono dígito.
// Normaliza antes de comparar.
const normalizarTelefone = (v: unknown) => {
  let d = soDigitos(v);
  if (d.length > 11 && d.startsWith("55")) d = d.slice(2);
  if (d.startsWith("0")) d = d.slice(1);
  return d;
};

/**
 * Número pronto para o WhatsApp: 55 + DDD + número. Cadastro com menos
 * de 10 dígitos (existem 3, sem DDD) não tem para onde mandar código.
 */
const numeroParaWhatsapp = (tel: unknown) => {
  const d = normalizarTelefone(tel);
  return d.length === 10 || d.length === 11 ? `55${d}` : null;
};

const novoSal = () =>
  btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));

const derivar = async (segredo: string, salB64: string) => {
  const sal = Uint8Array.from(atob(salB64), (c) => c.charCodeAt(0));
  const chave = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(segredo),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: sal, iterations: ITERACOES },
    chave,
    256,
  );
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
};

// Comparação de tempo constante: comparar com === deixa o tempo de
// resposta contar quantos caracteres bateram.
const igualSemVazar = (a: string, b: string) => {
  if (a.length !== b.length) return false;
  let dif = 0;
  for (let i = 0; i < a.length; i++) dif |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return dif === 0;
};

const pinValido = (p: unknown) => /^\d{4,6}$/.test(String(p ?? ""));

/** 6 dígitos sem viés: descarta sorteio acima do último múltiplo de 10⁶. */
const sortearCodigo = () => {
  const limite = Math.floor(0x100000000 / 1_000_000) * 1_000_000;
  const buf = new Uint32Array(1);
  do crypto.getRandomValues(buf); while (buf[0] >= limite);
  return String(buf[0] % 1_000_000).padStart(6, "0");
};

type Cliente = { id: string; nome_mae: string; email: string; telefone: string };
type Banco = ReturnType<typeof createClient>;

/**
 * Acha a cliente pelo e-mail OU pelo celular.
 *
 * Com "@" é e-mail: casamento exato, sem diferenciar maiúscula. Sem "@"
 * é celular: exato primeiro; se não achar, pelos 8 últimos dígitos
 * (resolve o nono dígito e o DDD colado). Se mais de uma bater, recusa —
 * melhor pedir de novo do que abrir a área da pessoa errada.
 */
const acharCliente = async (
  db: Banco,
  identificador: unknown,
): Promise<{ cliente?: Cliente; erro?: string }> => {
  const bruto = String(identificador ?? "").trim();
  if (!bruto) return { erro: "identificador_vazio" };

  const { data, error } = await db
    .from("clientes")
    .select("id,nome_mae,email,telefone");
  if (error) throw error;
  const lista = (data ?? []) as Cliente[];

  let achados: Cliente[];
  if (bruto.includes("@")) {
    const alvo = bruto.toLowerCase();
    achados = lista.filter((c) => String(c.email ?? "").trim().toLowerCase() === alvo);
  } else {
    const alvo = normalizarTelefone(bruto);
    if (alvo.length < 10) return { erro: "telefone_incompleto" };
    const comTel = lista.map((c) => ({ c, tel: normalizarTelefone(c.telefone) }));
    achados = comTel.filter((x) => x.tel === alvo).map((x) => x.c);
    if (achados.length === 0) {
      const fim = alvo.slice(-8);
      achados = comTel
        .filter((x) => x.tel.length >= 8 && x.tel.slice(-8) === fim)
        .map((x) => x.c);
    }
  }

  if (achados.length === 0) return { erro: "nao_encontrada" };
  if (achados.length > 1) return { erro: "ambiguo" };
  return { cliente: achados[0] };
};

const primeiroNome = (n: unknown) =>
  String(n ?? "").trim().split(/\s+/)[0] ?? "";

/**
 * O que a cliente digitou, mascarado: o log é lido por outras pessoas e
 * não precisa guardar e-mail ou telefone inteiro para dizer o que houve.
 * E-mail: 2 primeiras letras + domínio. Telefone: só os 4 últimos dígitos.
 */
const mascarar = (v: unknown) => {
  const bruto = String(v ?? "").trim();
  if (!bruto) return "(vazio)";
  if (bruto.includes("@")) {
    const [local, dominio] = bruto.toLowerCase().split("@");
    return `${local.slice(0, 2)}***@${(dominio ?? "").slice(0, 40)}`;
  }
  const d = soDigitos(bruto);
  return d.length ? `tel ${d.length} dígitos, final ${d.slice(-4)}` : "(sem dígitos)";
};

/** Rastro em `acesso_cliente_log`. Falhar aqui não derruba o pedido. */
const registrar = async (db: Banco, cliente_id: string | null, acao: string, detalhe?: string) => {
  const { error } = await db
    .from("acesso_cliente_log")
    .insert({ cliente_id, acao, detalhe: detalhe ?? null });
  if (error) console.error("area-cliente log:", error.message);
};

// ── Sessão ────────────────────────────────────────────────────────
// O token tem duas partes: `id.segredo`. O id acha a linha; o segredo é
// conferido contra o hash daquela linha (PBKDF2, igual ao PIN). Assim o
// banco nunca guarda o token, e achar a linha não exige varrer a tabela.
const criarSessao = async (db: Banco, cliente_id: string, de_onde?: string) => {
  const segredo = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const sal = novoSal();
  const expira_em = new Date(Date.now() + SESSAO_DIAS * 24 * 60 * 60000).toISOString();
  const { data, error } = await db
    .from("sessao_cliente")
    .insert({
      cliente_id,
      token_hash: await derivar(segredo, sal),
      token_salt: sal,
      expira_em,
      de_onde: de_onde ?? null,
    })
    .select("id")
    .single();
  if (error) throw error;
  return { token: `${data.id}.${segredo}`, expira_em };
};

const acharPelaSessao = async (db: Banco, token: unknown) => {
  const bruto = String(token ?? "");
  const corte = bruto.indexOf(".");
  if (corte < 1) return null;
  const id = bruto.slice(0, corte);
  const segredo = bruto.slice(corte + 1);
  if (!/^[0-9a-f-]{36}$/i.test(id) || segredo.length < 20) return null;

  const { data: sessao } = await db
    .from("sessao_cliente")
    .select("*")
    .eq("id", id)
    .maybeSingle();
  if (!sessao || sessao.revogada_em) return null;
  if (new Date(sessao.expira_em) <= new Date()) return null;
  if (!igualSemVazar(await derivar(segredo, sessao.token_salt), sessao.token_hash)) return null;

  const { data: cliente } = await db
    .from("clientes")
    .select("*")
    .eq("id", sessao.cliente_id)
    .maybeSingle();
  if (!cliente) return null;

  await db
    .from("sessao_cliente")
    .update({ ultimo_uso: new Date().toISOString() })
    .eq("id", sessao.id);
  return { sessao, cliente };
};

/** A ficha da cliente como ela pode ver: a dela, inteira. */
const fichaDaCliente = (c: Record<string, unknown>) => ({
  id: c.id, nome_mae: c.nome_mae, email: c.email, telefone: c.telefone,
  telefone_fixo: c.telefone_fixo, data_nascimento: c.data_nascimento,
  cpf_mae: c.cpf_mae, rg: c.rg,
  cep: c.cep, rua: c.rua, complemento: c.complemento, bairro: c.bairro, cidade: c.cidade,
  saldo_credito: c.saldo_credito, filhos: c.filhos, criada_em: c.created_at,
});

/**
 * Qual galeria vale, quando o ensaio tem mais de uma.
 *
 * Não deveria ter mais de uma — mas nada no banco impede, e nenhum
 * código conferia. A Luciana Galhardo ficou com duas no Natal dela: uma
 * vazia e desligada, e a de verdade com 162 fotos. A leitura daqui usava
 * `.maybeSingle()`, que **dá erro** com mais de uma linha. O erro era
 * descartado, `g` virava nulo e a resposta dizia "galeria: null": para a
 * cliente, as fotos simplesmente não existiam, sem erro nenhum na tela.
 *
 * Ordem de preferência: a que está no ar, depois a que já tem escolha
 * da cliente, depois a que tem mais foto. Assim a duplicata vazia nunca
 * ganha da galeria de verdade — nem agora, nem se alguma aparecer por
 * um caminho que ninguém previu.
 */
const pesoDaGaleria = (g: Record<string, unknown> | undefined) => [
  g?.ativa ? 1 : 0,
  Array.isArray(g?.selecao) && g!.selecao.length > 0 ? 1 : 0,
  Array.isArray(g?.fotos) ? (g!.fotos as unknown[]).length : 0,
];

const melhorGaleria = (
  a: Record<string, unknown> | undefined,
  b: Record<string, unknown> | undefined,
) => {
  if (!a) return b;
  if (!b) return a;
  const pa = pesoDaGaleria(a);
  const pb = pesoDaGaleria(b);
  for (let i = 0; i < pa.length; i++) {
    if (pa[i] !== pb[i]) return pa[i] > pb[i] ? a : b;
  }
  return a;
};

/** A galeria como ela pode ver: fotos, quantas incluídas, o que escolheu. */
const galeriaParaCliente = (g: Record<string, unknown>) => ({
  id: g.id,
  fotos: Array.isArray(g.fotos) ? g.fotos : [],
  fotos_incluidas: g.fotos_incluidas ?? 0,
  preco_foto_extra: g.preco_foto_extra ?? 0,
  selecao: Array.isArray(g.selecao) ? g.selecao : [],
  selecao_confirmada: !!g.selecao_confirmada,
  link_pagamento_extras: g.link_pagamento_extras ?? null,
});

type Envio = "ok" | "sem_whatsapp" | "falha_envio" | "envio_indisponivel";

/**
 * A WAME pode responder 200 com um erro dentro. Falhou se o status não é
 * 2xx, ou se o corpo traz `error` preenchido / `success: false`. Um
 * `"error": null` num sucesso não conta.
 */
const wameFalhou = (ok: boolean, corpo: string) => {
  if (!ok) return true;
  try {
    const d = JSON.parse(corpo) as Record<string, unknown>;
    return (d.error !== undefined && d.error !== null && d.error !== false) ||
      d.success === false || d.status === "error";
  } catch {
    return false;
  }
};

/**
 * Manda o código pela API oficial (WAME), com o modelo `codigo_acesso`.
 *
 * É modelo de AUTENTICAÇÃO: o texto é o da Meta ("123456 é seu código de
 * verificação. Para sua segurança, não o compartilhe.") com um botão de
 * copiar. O código vai duas vezes — no texto e no botão —, como a Meta
 * exige para esse tipo.
 *
 * A reserva pela Evolution saiu em 22/09 (Cloudfy cancelada).
 */
const mandarCodigo = async (numero: string, codigo: string): Promise<Envio> => {
  const chave = Deno.env.get("WAME_KEY");
  if (!chave) {
    console.error("area-cliente: WAME_KEY ausente");
    return "envio_indisponivel";
  }

  const cancelar = new AbortController();
  const relogio = setTimeout(() => cancelar.abort(), PRAZO_WAME_MS);
  try {
    const res = await fetch(`${WAME_URL}/${encodeURIComponent(chave)}/message/template`, {
      method: "POST",
      signal: cancelar.signal,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        to: numero,
        name: "codigo_acesso",
        language: "pt_BR",
        components: [
          { type: "body", parameters: [{ type: "text", text: codigo }] },
          { type: "button", sub_type: "url", index: "0", parameters: [{ type: "text", text: codigo }] },
        ],
      }),
    });
    const corpo = await res.text().catch(() => "");
    // Registra SEMPRE, inclusive quando dá certo. Em 09/10/2026 a WAME
    // respondeu 200 a três envios e a Meta não registrou nenhum no dia
    // ("0 mensagens enviadas"); sem o corpo da resposta de sucesso não
    // havia como saber o que ela estava devolvendo. O código sai
    // mascarado: isto vai para um registro que outras pessoas leem.
    console.log("area-cliente wame envio:", res.status, corpo.replaceAll(codigo, "······").slice(0, 400));
    if (!wameFalhou(res.ok, corpo)) return "ok";
    console.error("area-cliente wame:", res.status, corpo.slice(0, 400));
    return "falha_envio";
  } catch (e) {
    console.error("area-cliente wame:", e);
    return "falha_envio";
  } finally {
    clearTimeout(relogio);
  }
};

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return responder({ erro: "metodo" }, 405);

  const db = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    { auth: { persistSession: false } },
  );

  try {
    const corpo = await req.json().catch(() => ({}));
    const acao = String(corpo?.acao ?? "");

    // ── Ações que andam com a sessão, não com o identificador ──
    const COM_SESSAO = ["meus-dados", "atualizar-perfil", "sair", "minhas-fotos", "escolher-fotos"];
    if (COM_SESSAO.includes(acao)) {
      const dono = await acharPelaSessao(db, corpo?.token);
      if (!dono) return responder({ ok: false, motivo: "sessao_invalida" }, 401);
      const { sessao, cliente } = dono;

      if (acao === "sair") {
        await db
          .from("sessao_cliente")
          .update({ revogada_em: new Date().toISOString() })
          .eq("id", sessao.id);
        return responder({ ok: true });
      }

      if (acao === "meus-dados") {
        const { data: ags } = await db
          .from("agendamentos")
          .select(
            "id,servico,modalidade,data,hora,valor,status,pagamento_status,pagamento_link," +
              "contrato_numero,contrato_html,signature,signature_contratada,signature_responsavel," +
              "signed_at,parcelas_json,valor_permuta,credito_usado",
          )
          .eq("cliente_id", cliente.id)
          .order("data", { ascending: false });

        // Quais ensaios têm galeria no ar, para a tela mostrar o botão.
        const ids = (ags ?? []).map((a: Record<string, unknown>) => a.id);
        const { data: gals } = ids.length
          ? await db.from("galerias").select("agendamento_id,ativa,selecao,selecao_confirmada").in("agendamento_id", ids)
          : { data: [] };
        // Um `Map` montado por `.map()` guarda a ÚLTIMA linha de cada
        // ensaio, e o banco não promete ordem: num ensaio com duas
        // galerias, podia ficar com a desligada e o botão de escolher
        // desaparecia da tela da cliente.
        const porEnsaio = new Map<unknown, Record<string, unknown>>();
        for (const g of (gals ?? []) as Record<string, unknown>[]) {
          porEnsaio.set(
            g.agendamento_id,
            melhorGaleria(porEnsaio.get(g.agendamento_id), g)!,
          );
        }

        // As fotos PRONTAS, que é outra coisa da galeria de seleção: lá
        // ela escolhe, aqui ela baixa. O link chegava só pelo WhatsApp —
        // e WhatsApp some no meio da conversa. Vai o `token`, que é o
        // endereço da galeria; a página `/entrega/:token` confere tudo
        // de novo no servidor, então mandar o token aqui não abre porta
        // nenhuma que o link do WhatsApp já não abrisse.
        const { data: ents } = ids.length
          ? await db.from("entregas")
              .select("agendamento_id,token,publicada_em,apagada_em,expira_em")
              .in("agendamento_id", ids)
          : { data: [] };
        const entregaDoEnsaio = new Map(
          (ents ?? []).map((e: Record<string, unknown>) => [e.agendamento_id, e]),
        );

        const ensaios = (ags ?? []).map((a: Record<string, unknown>) => {
          const g = porEnsaio.get(a.id) as Record<string, unknown> | undefined;
          return {
            id: a.id, servico: a.servico, modalidade: a.modalidade,
            data: a.data, hora: a.hora, valor: a.valor,
            status: a.status, pagamento_status: a.pagamento_status,
            pagamento_link: a.pagamento_link,
            contrato_numero: a.contrato_numero,
            // O HTML do contrato não vem: são ~30 kB por contrato, e a
            // página de assinatura já busca o dela pelo link.
            tem_contrato: !!a.contrato_html,
            assinou_cliente: !!a.signature,
            assinou_responsavel: !!a.signature_responsavel,
            assinou_fotografa: !!a.signature_contratada,
            assinado_em: a.signed_at,
            parcelas: a.parcelas_json ?? null,
            galeria_no_ar: !!(g && g.ativa),
            escolhidas: Array.isArray(g?.selecao) ? (g!.selecao as unknown[]).length : 0,
            selecao_confirmada: !!g?.selecao_confirmada,
            // Só vai o token quando a entrega está publicada E ainda não
            // foi apagada — galeria vencida não ganha botão que leva a
            // uma página de "o prazo acabou".
            entrega_token: (() => {
              const e = entregaDoEnsaio.get(a.id) as Record<string, unknown> | undefined;
              return e && e.publicada_em && !e.apagada_em ? e.token : null;
            })(),
            entrega_ate: (() => {
              const e = entregaDoEnsaio.get(a.id) as Record<string, unknown> | undefined;
              return e && e.publicada_em && !e.apagada_em ? e.expira_em : null;
            })(),
          };
        });

        return responder({ ok: true, cliente: fichaDaCliente(cliente), ensaios });
      }

      if (acao === "atualizar-perfil") {
        const { data, error } = await db.rpc("perfil_cliente_atualizar", {
          p_cliente: cliente.id,
          p_campos: corpo?.campos ?? {},
        });
        if (error) throw error;
        const r = data as { ok: boolean; motivo?: string; campos?: Record<string, unknown> };
        if (r?.ok) {
          await registrar(db, cliente.id, "perfil_atualizado", Object.keys(r.campos ?? {}).join(", "));
          const { data: atual } = await db.from("clientes").select("*").eq("id", cliente.id).maybeSingle();
          return responder({ ok: true, cliente: fichaDaCliente(atual ?? cliente) });
        }
        return responder({ ok: false, motivo: r?.motivo ?? "erro_servidor" });
      }

      // ── Galeria: ver as fotos do ensaio dela ──
      // O ensaio precisa ser DELA, e a galeria precisa estar publicada.
      if (acao === "minhas-fotos" || acao === "escolher-fotos") {
        const agendamento_id = String(corpo?.agendamento_id ?? "");
        if (!ehUuid(agendamento_id)) return responder({ ok: false, motivo: "ensaio_invalido" });

        const { data: ag } = await db
          .from("agendamentos")
          .select("id,cliente_id,servico,modalidade,data")
          .eq("id", agendamento_id)
          .maybeSingle();
        if (!ag || ag.cliente_id !== cliente.id) {
          return responder({ ok: false, motivo: "nao_e_seu" }, 403);
        }

        // Lista, não `.maybeSingle()`: ver `melhorGaleria` acima. E o erro
        // da leitura sobe — antes era descartado, e falha de banco virava
        // "você não tem galeria" na cara da cliente.
        const { data: desteEnsaio, error: eGaleria } = await db
          .from("galerias")
          .select("*")
          .eq("agendamento_id", agendamento_id);
        if (eGaleria) throw eGaleria;
        const g = (desteEnsaio ?? []).reduce(
          (melhor: Record<string, unknown> | undefined, atual: Record<string, unknown>) =>
            melhorGaleria(melhor, atual),
          undefined,
        );
        if (!g || !g.ativa) return responder({ ok: true, galeria: null });

        if (acao === "minhas-fotos") {
          return responder({
            ok: true,
            galeria: galeriaParaCliente(g),
            ensaio: { id: ag.id, servico: ag.servico, modalidade: ag.modalidade, data: ag.data },
          });
        }

        // ── Galeria: gravar a escolha ──
        if (g.selecao_confirmada) {
          return responder({ ok: false, motivo: "ja_confirmada" });
        }
        const pedida = Array.isArray(corpo?.selecao) ? corpo.selecao : null;
        if (!pedida) return responder({ ok: false, motivo: "selecao_invalida" });
        if (pedida.length > MAX_FOTOS_ESCOLHIDAS) {
          return responder({ ok: false, motivo: "selecao_grande" });
        }

        // Só aceita foto que existe NESTA galeria: sem isso, dava para
        // mandar qualquer texto e sujar a lista que a Thais usa para editar.
        const disponiveis = new Set(
          (Array.isArray(g.fotos) ? g.fotos : []).map((f: Record<string, unknown>) => String(f?.url ?? "")),
        );
        const escolhidas = [...new Set(pedida.map((u: unknown) => String(u ?? "")))].filter((u) => disponiveis.has(u));
        if (escolhidas.length !== pedida.length) {
          return responder({ ok: false, motivo: "foto_de_fora" });
        }

        const confirmar = corpo?.confirmar === true;
        const { data: salva, error: eSalva } = await db
          .from("galerias")
          .update({ selecao: escolhidas, selecao_confirmada: confirmar })
          .eq("id", g.id)
          .eq("selecao_confirmada", false)
          .select("*")
          .maybeSingle();
        if (eSalva) throw eSalva;
        if (!salva) return responder({ ok: false, motivo: "ja_confirmada" });

        await registrar(
          db,
          cliente.id,
          confirmar ? "selecao_confirmada" : "selecao_salva",
          `${escolhidas.length} foto(s)`,
        );
        return responder({ ok: true, galeria: galeriaParaCliente(salva) });
      }
    }

    // `telefone` é o nome antigo do campo — o app publicado ainda usa.
    const identificador = corpo?.identificador ?? corpo?.telefone;
    const achado = await acharCliente(db, identificador);
    if (achado.erro) {
      // Sem cliente, sem cliente_id: o que ela digitou (mascarado) é o
      // único rastro de por que não entrou. Vazio não é falha de
      // cliente, é tela em branco — não polui o log.
      if (achado.erro !== "identificador_vazio") {
        await registrar(
          db,
          null,
          "identificador_falhou",
          `${acao || "?"}: ${achado.erro} — digitou ${mascarar(identificador)}`,
        );
      }
      return responder({ ok: false, motivo: achado.erro });
    }
    const cliente = achado.cliente!;

    const { data: acesso } = await db
      .from("acesso_cliente")
      .select("*")
      .eq("cliente_id", cliente.id)
      .maybeSingle();

    // ── Quem é você? Só o suficiente para a tela dar bom-dia. ──
    if (acao === "iniciar") {
      return responder({
        ok: true,
        nome: primeiroNome(cliente.nome_mae),
        tem_pin: !!acesso,
      });
    }

    // ── Primeiro PIN: só com código. ──
    if (acao === "criar-pin") {
      return responder({ ok: false, motivo: acesso ? "ja_tem_pin" : "codigo_necessario" });
    }

    // ── Entrar. Confere contra ESTA cliente, e só ela. ──
    if (acao === "validar-pin") {
      if (!acesso) return responder({ ok: false, motivo: "sem_pin" });

      if (acesso.bloqueado_ate && new Date(acesso.bloqueado_ate) > new Date()) {
        const faltam = Math.ceil(
          (new Date(acesso.bloqueado_ate).getTime() - Date.now()) / 60000,
        );
        return responder({ ok: false, motivo: "bloqueado", minutos: faltam });
      }

      if (!pinValido(corpo?.pin)) {
        return responder({ ok: false, motivo: "pin_invalido" });
      }

      const hash = await derivar(String(corpo.pin), acesso.pin_salt);
      if (!igualSemVazar(hash, acesso.pin_hash)) {
        const tentativas = (acesso.tentativas ?? 0) + 1;
        const trancar = tentativas >= MAX_TENTATIVAS;
        await db
          .from("acesso_cliente")
          .update({
            tentativas: trancar ? 0 : tentativas,
            bloqueado_ate: trancar
              ? new Date(Date.now() + BLOQUEIO_MINUTOS * 60000).toISOString()
              : null,
            atualizado_em: new Date().toISOString(),
          })
          .eq("cliente_id", cliente.id);
        if (trancar) {
          await registrar(db, cliente.id, "pin_bloqueado", `${MAX_TENTATIVAS} erros seguidos, ${BLOQUEIO_MINUTOS} min`);
        }
        return responder({
          ok: false,
          motivo: trancar ? "bloqueado" : "pin_errado",
          minutos: trancar ? BLOQUEIO_MINUTOS : undefined,
          restantes: trancar ? 0 : MAX_TENTATIVAS - tentativas,
        });
      }

      await db
        .from("acesso_cliente")
        .update({
          tentativas: 0,
          bloqueado_ate: null,
          atualizado_em: new Date().toISOString(),
        })
        .eq("cliente_id", cliente.id);

      const sessao = await criarSessao(db, cliente.id, "entrou com PIN");
      return responder({ ok: true, cliente, ...sessao });
    }

    // ── Trocar o PIN: precisa saber o atual. ──
    if (acao === "trocar-pin") {
      if (!acesso) return responder({ ok: false, motivo: "sem_pin" });
      if (!pinValido(corpo?.pin_novo)) {
        return responder({ ok: false, motivo: "pin_invalido" });
      }
      const hash = await derivar(String(corpo?.pin_atual ?? ""), acesso.pin_salt);
      if (!igualSemVazar(hash, acesso.pin_hash)) {
        return responder({ ok: false, motivo: "pin_errado" });
      }
      const sal = novoSal();
      const novo = await derivar(String(corpo.pin_novo), sal);
      const { error } = await db
        .from("acesso_cliente")
        .update({
          pin_hash: novo,
          pin_salt: sal,
          tentativas: 0,
          bloqueado_ate: null,
          atualizado_em: new Date().toISOString(),
        })
        .eq("cliente_id", cliente.id);
      if (error) throw error;

      // PIN trocado derruba as sessões antigas: se ela trocou por
      // desconfiança, o celular de quem estava dentro para de valer.
      await db
        .from("sessao_cliente")
        .update({ revogada_em: new Date().toISOString() })
        .eq("cliente_id", cliente.id)
        .is("revogada_em", null);

      const sessao = await criarSessao(db, cliente.id, "trocou o PIN");
      return responder({ ok: true, cliente, ...sessao });
    }

    // ── Esqueci a senha, passo 1: código no WhatsApp do cadastro. ──
    if (acao === "enviar-codigo") {
      const numero = numeroParaWhatsapp(cliente.telefone);
      if (!numero) {
        await registrar(db, cliente.id, "envio_codigo_falhou", "cadastro_incompleto: telefone sem DDD ou inválido");
        return responder({ ok: false, motivo: "cadastro_incompleto" });
      }

      const umaHoraAtras = new Date(Date.now() - 60 * 60000).toISOString();
      const { count, error: eConta } = await db
        .from("codigo_acesso")
        .select("id", { count: "exact", head: true })
        .eq("cliente_id", cliente.id)
        .gte("criado_em", umaHoraAtras);
      if (eConta) throw eConta;
      if ((count ?? 0) >= CODIGOS_POR_HORA) {
        await registrar(db, cliente.id, "envio_codigo_falhou", `muitos_codigos: ${count} na última hora`);
        return responder({ ok: false, motivo: "muitos_codigos" });
      }

      const codigo = sortearCodigo();
      const sal = novoSal();
      const { data: linha, error: eIns } = await db
        .from("codigo_acesso")
        .insert({
          cliente_id: cliente.id,
          codigo_hash: await derivar(codigo, sal),
          codigo_salt: sal,
          expira_em: new Date(Date.now() + CODIGO_VALIDADE_MIN * 60000).toISOString(),
        })
        .select("id")
        .single();
      if (eIns) throw eIns;

      const envio = await mandarCodigo(numero, codigo);
      if (envio !== "ok") {
        // Código que não chegou não pode gastar a cota da hora.
        await db.from("codigo_acesso").delete().eq("id", linha.id);
        await registrar(db, cliente.id, "envio_codigo_falhou", `${envio}: whatsapp final ${numero.slice(-2)}`);
        return responder({ ok: false, motivo: envio });
      }

      // Só o último código vale: os anteriores ainda abertos vencem agora.
      await db
        .from("codigo_acesso")
        .update({ expira_em: new Date().toISOString() })
        .eq("cliente_id", cliente.id)
        .is("usado_em", null)
        .neq("id", linha.id);

      const final = numero.slice(-2);
      await registrar(db, cliente.id, "codigo_enviado", `whatsapp final ${final}`);
      return responder({ ok: true, final, minutos: CODIGO_VALIDADE_MIN });
    }

    // ── Esqueci a senha, passo 2: código certo troca o PIN. ──
    if (acao === "redefinir-pin") {
      const codigo = soDigitos(corpo?.codigo);
      if (!/^\d{6}$/.test(codigo)) {
        await registrar(db, cliente.id, "codigo_falhou", "codigo_invalido: não tem 6 dígitos");
        return responder({ ok: false, motivo: "codigo_invalido" });
      }
      if (!pinValido(corpo?.pin)) {
        await registrar(db, cliente.id, "codigo_falhou", "pin_invalido: novo PIN fora de 4 a 6 dígitos");
        return responder({ ok: false, motivo: "pin_invalido" });
      }

      const agora = new Date();
      const { data: ultimo, error: eCod } = await db
        .from("codigo_acesso")
        .select("*")
        .eq("cliente_id", cliente.id)
        .is("usado_em", null)
        .order("criado_em", { ascending: false })
        .limit(1)
        .maybeSingle();
      if (eCod) throw eCod;
      if (!ultimo || new Date(ultimo.expira_em) <= agora) {
        await registrar(db, cliente.id, "codigo_falhou", ultimo ? "codigo_vencido" : "codigo_vencido: nenhum código aberto");
        return responder({ ok: false, motivo: "codigo_vencido" });
      }
      if ((ultimo.tentativas ?? 0) >= CODIGO_MAX_TENTATIVAS) {
        await registrar(db, cliente.id, "codigo_falhou", "codigo_bloqueado: tentativas esgotadas");
        return responder({ ok: false, motivo: "codigo_bloqueado" });
      }

      const confere = igualSemVazar(
        await derivar(codigo, ultimo.codigo_salt),
        ultimo.codigo_hash,
      );
      if (!confere) {
        const t = (ultimo.tentativas ?? 0) + 1;
        await db.from("codigo_acesso").update({ tentativas: t }).eq("id", ultimo.id);
        await registrar(db, cliente.id, "codigo_falhou", `codigo_errado: tentativa ${t} de ${CODIGO_MAX_TENTATIVAS}`);
        return t >= CODIGO_MAX_TENTATIVAS
          ? responder({ ok: false, motivo: "codigo_bloqueado" })
          : responder({ ok: false, motivo: "codigo_errado", restantes: CODIGO_MAX_TENTATIVAS - t });
      }

      // Marca o código como usado ANTES de gravar o PIN, e só se ainda
      // estiver livre: duas abas com o mesmo código, só uma passa.
      const { data: marcado } = await db
        .from("codigo_acesso")
        .update({ usado_em: agora.toISOString() })
        .eq("id", ultimo.id)
        .is("usado_em", null)
        .select("id");
      if (!marcado?.length) return responder({ ok: false, motivo: "codigo_vencido" });

      const sal = novoSal();
      const campos = {
        pin_hash: await derivar(String(corpo.pin), sal),
        pin_salt: sal,
        tentativas: 0,
        bloqueado_ate: null,
        atualizado_em: agora.toISOString(),
      };
      const { error: eGrava } = acesso
        ? await db.from("acesso_cliente").update(campos).eq("cliente_id", cliente.id)
        : await db.from("acesso_cliente").insert({ cliente_id: cliente.id, ...campos });
      if (eGrava) throw eGrava;

      // Redefinir senha derruba o que estava aberto antes.
      await db
        .from("sessao_cliente")
        .update({ revogada_em: agora.toISOString() })
        .eq("cliente_id", cliente.id)
        .is("revogada_em", null);

      await registrar(
        db,
        cliente.id,
        "pin_redefinido",
        acesso ? "substituiu o PIN existente" : "criou o primeiro PIN",
      );
      const sessao = await criarSessao(db, cliente.id, "redefiniu o PIN");
      return responder({ ok: true, cliente, ...sessao });
    }

    return responder({ ok: false, motivo: "acao_desconhecida" }, 400);
  } catch (e) {
    console.error("area-cliente:", e);
    return responder({ ok: false, motivo: "erro_servidor" }, 500);
  }
});

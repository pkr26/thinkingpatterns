/**
 * The Spanish catalog (2026-09-19 i18n wave). Mirrors every key in en.ts —
 * the i18n test asserts completeness against the English catalog.
 *
 * Voice rules (mental-health safe-messaging):
 *  - calm, warm, plain Spanish; never shaming, never prescriptive
 *    (no "deberías" in question copy — the "no advice" philosophy holds);
 *  - neutral phrasing where possible, "usted" when a person must be
 *    addressed directly;
 *  - crisis phone numbers (988, 741741, 911) and URLs are NEVER
 *    translated — they are identical to the English catalog by design.
 */

export const es: Record<string, string> = {
  // ---------------------------------------------------------------- common
  "common.notNow": "Ahora no",
  "common.cancel": "Cancelar",
  "common.continue": "Continuar",
  "common.ok": "Aceptar",
  "common.tryAgain": "Intentar de nuevo",
  "common.back": "Volver",
  "common.delete": "Eliminar",
  "common.deletePermanently": "Eliminar definitivamente",
  "common.finalConfirmation": "Confirmación final",
  "common.day": "día",
  "common.days": "días",
  "common.accountMissing": "falta el id de la cuenta — inicie sesión de nuevo",
  "common.sessionDamagedTitle": "La sesión está dañada",
  "common.wrongPassword": "Contraseña incorrecta.",
  "common.passwordPlaceholder": "contraseña",
  "common.passwordA11y": "Contraseña",
  "common.passwordConfirmA11y": "Confirmación de contraseña",
  "common.verifying": "Verificando…",
  "common.confirmWithPassword": "Confirmar con contraseña",
  "common.couldNotVerifyTitle": "No se pudo verificar",
  "common.reauthLocked": "La bóveda está bloqueada — desbloquéela primero.",
  "common.reauthNoAccount": "No hay ninguna cuenta guardada en este dispositivo — inicie sesión de nuevo.",
  "common.reauthOffline": "No se puede verificar su contraseña sin conexión en este momento — inténtelo de nuevo cuando haya conexión.",
  "common.passwordMismatchTitle": "Esa contraseña no coincide",
  "common.passwordMismatchBody": "Revísela e inténtelo de nuevo — no se cambió nada.",
  "common.sessionExpiredTitle": "La sesión expiró",
  "common.unlockAgainBody": "Vuelva a desbloquear.",
  "common.couldNotCompleteTitle": "No se pudo completar",
  "common.neverWrongMove": "Hablar con un profesional nunca es un paso equivocado.",
  // 2026-09-27: la etiqueta de acción del plan de seguridad local — la
  // comparten el enlace de la pantalla de crisis, el tercer botón de los
  // diálogos de crisis y la fila de Ajustes.
  "common.makeSafetyPlan": "Hacer un plan de seguridad",
  "common.streakOne": "Racha de escritura: {count} día",
  "common.streakMany": "Racha de escritura: {count} días",

  // ---------------------------------------------------------------- errors
  "errors.offline": "No se pudo conectar con el servidor — revise su conexión.",
  "errors.sessionExpired": "La sesión expiró — vuelva a desbloquear.",
  "errors.forbidden": "El servidor rechazó esa solicitud.",
  "errors.notFound": "Eso ya no está en el servidor.",
  "errors.conflict": "Eso entra en conflicto con algo que el servidor ya tiene.",
  "errors.tooLarge": "Es más información de la que el servidor puede aceptar.",
  "errors.rateLimited": "Demasiados intentos — espere un momento e inténtelo de nuevo.",
  "errors.serverError": "El servidor tuvo un problema — inténtelo de nuevo en un momento.",
  "errors.rejected": "El servidor no aceptó esa solicitud.",
  "errors.generic": "Algo salió mal — inténtelo de nuevo.",

  // ------------------------------------------------------------ nav / buttons
  "nav.today": "Hoy",
  "nav.history": "Historial",
  "nav.patterns": "Patrones",
  "nav.question": "Pregunta",
  "nav.settings": "Ajustes",
  "nav.getHelp": "Ayuda",
  "nav.a11y": "Navegación principal",
  "nav.getHelpA11y": "Buscar ayuda — recursos de crisis",
  // 2026-09-26 audit M-M4: títulos de pantalla del navegador (antes fijos
  // en inglés). nav.question sigue siendo la pestaña inferior; el ENCABEZADO
  // de la pantalla de pregunta lee más largo.
  "nav.questionTitle": "Una pregunta",
  "nav.therapist": "Mi terapeuta",
  "nav.measures": "Cuestionarios de bienestar",
  "nav.privacy": "Privacidad",
  "buttons.needHelp": "¿Necesita ayuda ahora? Recursos de crisis",

  // -------------------------------------------------------------- calendar
  "calendar.a11y": "Calendario, {month}. Los puntos marcan los días con entradas.",
  "calendar.prevMonth": "Mes anterior",
  "calendar.nextMonth": "Mes siguiente",
  "calendar.dayJournaled": "{date}, con entrada",
  "calendar.dayJournaledSelected": "{date}, con entrada, seleccionado",
  "calendar.dayNoEntry": "{date}, sin entrada",

  // ---------------------------------------------------------------- crisis
  // SAFETY-CRITICAL copy: numbers and URLs never change per locale.
  "crisis.title": "Si está pensando en hacerse daño",
  "crisis.subtitle":
    "Por favor, busque apoyo ahora mismo. Estos servicios son gratuitos y confidenciales, y los atienden personas capacitadas — las 24 horas del día.",
  "crisis.whatToExpect":
    "Qué esperar al llamar o escribir: responde una persona consejera capacitada, y usted puede decir tanto o tan poco como quiera — no hay guion ni una forma equivocada de empezar.",
  "crisis.openFailedTitle": "No se pudo abrir desde aquí",
  "crisis.call988": "Llame o envíe un mensaje de texto al 988",
  "crisis.call988.detail": "988 Suicide & Crisis Lifeline — llame al 988 o envíe un mensaje de texto, a cualquier hora",
  "crisis.call988.fallback": "Aún puede marcar o enviar un mensaje de texto al 988 desde su teléfono — es gratuito y atienden 24/7.",
  "crisis.text741741": "Envíe HOME por mensaje de texto al 741741",
  "crisis.text741741.detail": "Crisis Text Line — conversación por mensaje de texto con una persona consejera capacitada",
  "crisis.text741741.fallback": "Aún puede enviar HOME al 741741 desde su aplicación de mensajes.",
  "crisis.chat": "Chatear en 988lifeline.org",
  "crisis.chat.detail": "La misma línea de ayuda, en su navegador — sin necesidad de llamar",
  "crisis.chat.fallback": "Aún puede visitar 988lifeline.org/chat en un navegador.",
  "crisis.emergency": "Llamar al 911 (EE. UU.)",
  "crisis.emergency.us": "Llamar al 911",
  "crisis.emergency.detail": "Si está en peligro inmediato o ya se ha hecho daño",
  "crisis.emergency.fallback": "Aún puede marcar el 911 desde su teléfono.",
  "crisis.findhelpline": "Abrir findahelpline.com",
  "crisis.findhelpline.detail": "Abrir findahelpline.com — líneas de crisis de todo el mundo",
  "crisis.findhelpline.fallback": "Aún puede visitar findahelpline.com en un navegador.",
  // El plan de seguridad local (2026-09-27): un complemento DESPUÉS de los
  // recursos, nunca una puerta antes de ellos. El enlace aparece solo con
  // la bóveda desbloqueada; los recursos de arriba nunca dependen de él.
  "crisis.makePlanA11y": "Hacer un plan de seguridad — privado, cifrado en este dispositivo",
  "crisis.makePlanNote": "Privado, cifrado en este dispositivo — escriba lo que le ayuda a atravesarlo.",
  "crisis.localeNote": "Estos son servicios de EE. UU. Fuera de EE. UU., encuentre su línea local en findahelpline.com.",
  "crisis.regionNote": "Su región no parece ser EE. UU. — busque primero su línea local:",
  "crisis.usServicesNote": "En EE. UU., estos son los servicios nacionales (988 y 741741 son solo de EE. UU.):",
  "crisis.go": "Ir",
  "crisis.actionA11y": "{label} — {detail}",
  "crisis.disclaimer":
    "MindPattern es un diario que le muestra sus propios patrones. No es terapia, no es un dispositivo médico y no es un servicio de emergencia. Hablar con un profesional nunca es un paso equivocado.",

  // ---------------------------------------------------------------- unlock
  "unlock.title": "Bloqueado",
  "unlock.body":
    "Su diario está cifrado con llaves que solo usted tiene. Vuelva a escribir su contraseña para desbloquear este dispositivo. Cuando pide sus patrones, la llave viaja al servidor una sola vez — se mantiene en memoria y luego se destruye. Nada más sale jamás de su dispositivo.",
  "unlock.biometric": "Desbloquear con biometría",
  "unlock.biometricFailed": "El desbloqueo biométrico no funcionó — su contraseña siempre funciona abajo.",
  "unlock.button": "Desbloquear",
  "unlock.signOutInstead": "Cerrar sesión",
  "unlock.failedTitle": "No se pudo desbloquear",
  "unlock.noAccount": "no hay ninguna cuenta guardada en este dispositivo — inicie sesión",
  "unlock.offlineNotEnabled":
    "el desbloqueo sin conexión aún no está activado en este dispositivo — inicie sesión una vez con conexión para activarlo",
  // Sobrellave v2 (2026-09-26): la contraseña fue aceptada (en línea) o el
  // sobre guardado era legible, pero el sobre no se pudo abrir o no sirve —
  // un mensaje sereno sobre el servidor o los datos, nunca "contraseña incorrecta".
  "unlock.envelopeFailed":
    "el sobre de llaves de esta cuenta no se pudo abrir en este servidor. No se cambió nada — inténtelo de nuevo y contacte a soporte si se repite.",
  // Auditoría independiente 27/09/2026 (P2): el inicio de sesión en línea
  // funcionó, pero la consulta del esquema de llaves falló y este dispositivo
  // solo tiene un marcador de esquema obsoleto (o nada). Un marcador por sí
  // solo no autoriza derivar llaves v1: hoy es seguro solo porque v1→v2
  // envuelve la misma llave de datos, y cualquier rotación futura de esquema
  // convertiría esto en una escritura silenciosa con la llave equivocada. Se
  // rechaza con un mensaje honesto de reintento — no se desbloqueó ni se
  // cambió nada.
  "unlock.schemeUnconfirmed":
    "No pudimos confirmar ahora cómo está configurado el cifrado de su cuenta. Compruebe su conexión e inténtelo de nuevo en un momento — no se desbloqueó nada y no se cambió nada.",

  // ----------------------------------------------------------------- login
  "login.subtitle": "Sus patrones, a partir de sus palabras. Cifrado en este dispositivo.",
  "login.usernamePlaceholder": "usuario",
  "login.usernameA11y": "Usuario",
  "login.confirmPlaceholder": "confirmar contraseña",
  "login.confirmA11y": "Confirmar contraseña",
  "login.strength": "Seguridad de la contraseña: {label}.",
  "login.strength.weak": "débil",
  "login.strength.fair": "aceptable",
  "login.strength.strong": "fuerte",
  "login.strengthWeakHint": "Más larga es más segura — piense en una frase corta o en varias palabras.",
  "login.strengthFairHint": "Buen comienzo — más longitud o un símbolo la hacen más segura.",
  "login.mismatchInline": "Las contraseñas no coinciden.",
  "login.mismatchTitle": "Las contraseñas no coinciden",
  "login.mismatchBody": "Escriba la misma contraseña dos veces — no hay forma de recuperarla si se pierde.",
  "login.policyShortTitle": "Contraseña demasiado corta",
  "login.policyVarietyTitle": "La contraseña necesita más variedad",
  "login.policyMin": "Use al menos 12 caracteres — esta contraseña genera sus llaves de cifrado.",
  "login.policyVariety": "Use una frase de 16 caracteres, o 12+ caracteres de al menos tres tipos distintos.",
  "login.policyCommon": "Esa contraseña es demasiado fácil de adivinar. Evite palabras comunes, caracteres repetidos y secuencias del teclado.",
  "login.serverLabel": "Servidor: {server}",
  "login.serverA11y": "Dirección del servidor seleccionado",
  "login.serverChangedWarning":
    "Este servidor es distinto al que usa normalmente. Verifique la dirección antes de escribir su contraseña: su contraseña es su clave de cifrado y no hay forma de recuperarla.",
  "login.serverChangedA11y": "Aviso: la dirección del servidor cambió",
  "login.trustThisServer": "Confío en este servidor",  "login.policyHint":
    "Elija una contraseña de al menos 12 caracteres — una frase de 16 caracteres, o 12–15 caracteres de al menos tres tipos distintos.",
  "login.noReset":
    "No existe recuperación de contraseña. Si la olvida, nadie — incluyéndonos a nosotros — podrá recuperar su diario.",
  "login.signIn": "Iniciar sesión",
  "login.createAccount": "Crear cuenta",
  // PUERTA DE EDAD (2026-09-27, clínica): el registro exige una
  // declaración explícita de 18 años o más. Copia de seguridad crítica —
  // una afirmación llana, idéntica en significado en cada idioma.
  "login.ageConfirm": "Tengo 18 años o más",
  "login.ageConfirmA11y": "Confirmación de edad — tengo 18 años o más",
  "login.switchToRegister": "¿Primera vez aquí? Crear una cuenta",
  "login.switchToSignIn": "¿Ya tiene una cuenta? Iniciar sesión",
  "login.registerFailedTitle": "No se pudo crear la cuenta",
  "login.signInFailedTitle": "Error al iniciar sesión",
  "login.badCredentials": "Ese usuario o contraseña no coincide.",
  "login.usernameTaken": "Ese nombre de usuario ya está en uso. Pruebe otro, o inicie sesión.",
  // L-65: la cuenta SÍ se creó, pero un paso posterior falló en este
  // dispositivo — la salida es iniciar sesión, no volver a registrarse.
  "login.registerPartialTitle": "Cuenta creada",
  "login.registerPartialBody":
    "Su cuenta fue creada, pero este dispositivo no pudo terminar de iniciar la sesión. Cambie a iniciar sesión y use su nuevo usuario y contraseña.",
  // Sobrellave v2 (2026-09-26): la contraseña fue aceptada en línea, pero el
  // sobre de llaves de la cuenta no se abrió con ella en este servidor — no
  // es un mensaje de contraseña incorrecta.
  "login.envelopeFailed":
    "Su contraseña fue aceptada, pero el sobre de llaves de esta cuenta no se pudo abrir en este servidor. No se cambió nada — inténtelo de nuevo, o contacte a soporte si se repite.",
  "login.envelopeUnrecognized":
    "No pudimos verificar su clave de cifrado — el servidor envió una respuesta que esta aplicación no entiende. No se cambió nada; actualizar la aplicación puede ayudar.",

  // ------------------------------------------------------------- onboarding
  "onboarding.panel1Title": "Escriba cada día",
  "onboarding.panel1Body":
    "Después de 30 días de escritura, la app le muestra patrones demasiado lentos para notarlos por su cuenta — cada uno con la evidencia que lo respalda. Nunca consejos, nunca un diagnóstico.",
  "onboarding.panel2Title": "Sus palabras siguen siendo suyas",
  "onboarding.panel2Body":
    "Su contraseña genera las llaves de cifrado en este dispositivo, y todo lo que escribe se cifra antes de salir de él — el servidor guarda solo texto cifrado. La única excepción: cuando usted mismo inicia un análisis de patrones, su llave se usa una vez — se mantiene en memoria por un máximo de 5 minutos y luego se destruye. Nunca se guarda.",
  "onboarding.panel3Title": "Cuide su contraseña",
  "onboarding.panel3Body":
    "No existe recuperación de contraseña — anote su contraseña en un lugar seguro. Si se pierde, nadie, incluyéndonos a nosotros, podrá recuperar su diario.",
  "onboarding.stepOf": "{current} de {total}",
  "onboarding.remindQuestion": "¿Quiere un recordatorio amable cada día? Puede cambiarlo cuando quiera en Ajustes.",
  "onboarding.readPrivacy": "Leer la política de privacidad",
  // 2026-09-27: el mínimo de edad pasó a 18 con la puerta de edad del
  // registro (login.ageConfirm) — esta línea declara el mismo mínimo para
  // que nunca se contradigan.
  "onboarding.ageNotice": "MindPattern es para personas de 18 años o más — al continuar, usted lo confirma.",
  "onboarding.start": "Entiendo — empezar a escribir",
  "onboarding.continueA11y": "Continuar al panel {next} de {total}",

  // ---------------------------------------------------------------- privacy
  "privacy.headline": "Privacidad, en lenguaje claro",
  "privacy.s1Title": "Qué se cifra",
  "privacy.s1Body":
    "Todo lo que escribe. Su contraseña genera las llaves de cifrado en este dispositivo, y las entradas se cifran antes de salir de él. El servidor guarda solo texto cifrado. No existe recuperación de contraseña. Si la olvida, nadie — incluyéndonos a nosotros — podrá recuperar su diario.",
  "privacy.s2Title": "Qué ve el servidor",
  "privacy.s2Body":
    "Su nombre de usuario, las fechas del calendario en que escribió, cuándo llegó cada entrada y el tamaño de cada entrada cifrada. Una filtración de la base de datos del servidor revela cuándo y cuánto escribió — nunca qué.",
  "privacy.s3Title": "La única excepción: el análisis de patrones",
  "privacy.s3Body":
    "Los patrones los calcula el servidor, que necesita sus entradas descifradas una sola vez para hacerlo. Cuando usted inicia un análisis, su llave se envía una vez por una conexión cifrada, se mantiene en memoria por un máximo de 5 minutos, se usa y se destruye. Nunca se guarda, y nunca se envía por ninguna otra razón.",
  "privacy.s4Title": "Análisis con IA (opcional)",
  "privacy.s4Body":
    "Desactivado por defecto en todas las cuentas. Si lo activa, sus entradas descifradas se envían a un proveedor de IA externo elegido por el operador del servidor, y aplica la política de retención de datos de ese proveedor. Activarlo pide su contraseña, así que un teléfono prestado no puede cambiarlo.",
  "privacy.s5Title": "Eliminar sus datos",
  "privacy.s5Body":
    "Eliminar su cuenta quita sus entradas, patrones y cuenta de la base de datos activa. Las copias de seguridad y los registros del servidor caducan según el calendario del propio operador — la eliminación no puede retroceder sobre ellos. Un paquete exportado lo incluye todo y sigue siendo suyo, para conservarlo o eliminarlo.",
  "privacy.footnote": "Esta política vive dentro de la app — leerla no requiere conexión y no deja rastro en ningún lugar.",

  // ------------------------------------------------------------------ entry
  "entry.daysToPatterns": "{active}/{total} días para sus patrones",
  "entry.patternsUnlocked": "Patrones desbloqueados",
  "entry.progressA11y": "Progreso hacia sus patrones: {done} de {total} días",
  "entry.wroteToday": "Hoy ya escribió",
  "entry.draftRestored": "Borrador restaurado",
  "entry.readyBody":
    "{days} días de escritura — sus patrones están listos para una primera mirada. Aún no todo habrá salido a la luz: los patrones se ganan su lugar a medida que se acumula la evidencia, y lo que aparezca llega con los días que lo respaldan.",
  "entry.seePatterns": "Ver sus patrones",
  "entry.seePatternsA11y": "Ver sus patrones",
  "entry.dismissReadyA11y": "Descartar el aviso de patrones listos",
  "entry.startWith": "Empezar con: {chip}",
  "entry.placeholder": "¿Qué hay hoy?",
  "entry.journalA11y": "Entrada del diario",
  "entry.charCount": "{current} / {max}",
  "entry.hideKeyboard": "Ocultar teclado",
  "entry.showDetails": "Agregar detalles (opcional)",
  "entry.hideDetails": "Ocultar detalles",
  "entry.detailsAdded": "Detalles agregados: {channels}",
  "entry.detailsAddedA11y": "Detalles agregados: {channels}. Toque para mostrar los detalles.",
  "entry.channelMood": "ánimo",
  "entry.channelEnergy": "energía",
  "entry.channelSleep": "sueño",
  "entry.channelTags": "etiquetas",
  "entry.moodQuestion": "¿Cómo se siente el día de hoy? Opcional — un toque basta.",
  "entry.moodCheckInA11y": "Registro de ánimo",
  "entry.moodOptionA11y": "Ánimo: {label}",
  "entry.energyQuestion": "¿Y su energía? Opcional.",
  "entry.energyCheckInA11y": "Registro de energía",
  "entry.energyOptionA11y": "Energía: {label}",
  "entry.sleepQuestion": "¿Cómo durmió? Opcional.",
  "entry.sleepA11y": "Calidad del sueño",
  "entry.sleepOptionA11y": "Sueño: {label}",
  "entry.tagsQuestion": "¿Qué marcó el día? Opcional — toque los que quiera.",
  "entry.tagsA11y": "Etiquetas del día",
  "entry.tagA11y": "Etiqueta: {tag}",
  "entry.save": "Guardar entrada",
  "entry.saved": "Guardado ✓",
  "entry.savedOffline": "Guardado — se sincronizará cuando haya conexión",
  "entry.tooLongTitle": "Entrada demasiado larga",
  "entry.tooLongBody": "Las entradas están limitadas a {max} caracteres.",
  "entry.sessionDamagedBody": "Falta el id de la cuenta — inicie sesión de nuevo. Su entrada sigue en pantalla.",
  "entry.crisisAlertTitle": "Hay apoyo disponible",
  "entry.crisisAlertBody":
    "Algo de lo que escribió suena a un momento muy pesado. Sea lo que esté cargando, no tiene que cargarlo en soledad — ayuda gratuita y confidencial está a un toque.",
  "entry.crisisViewResources": "Ver recursos de apoyo",
  "entry.sessionExpiredBody": "Vuelva a desbloquear — su entrada seguirá aquí.",
  "entry.notAcceptedTitle": "Entrada no aceptada",
  "entry.notAcceptedBody": "El servidor no pudo guardar esta entrada tal como está. Su entrada sigue en pantalla.",
  "entry.queueFullTitle": "Almacenamiento sin conexión lleno",
  "entry.queueFullBody":
    "Sus entradas sin sincronizar más antiguas están protegidas — conéctese y sincronice antes de escribir más. Esta entrada sigue en pantalla.",
  "entry.queueAbandonedTitle": "No se guardó",
  "entry.queueAbandonedBody":
    "La cola sin conexión se vació mientras se guardaba (¿cerró la sesión?). Su entrada sigue en pantalla.",
  "entry.couldNotSaveTitle": "No se pudo guardar",

  // ------------------------------------- check-in vocabulary (audit fix 21)
  // Etiquetas de visualización por VALOR de la opción; los valores del
  // contrato — los números y los tokens de etiqueta en inglés de
  // src/mood.ts — nunca se traducen (el motor del servidor los lee).
  "mood.option.heavy": "Pesado",
  "mood.option.low": "Bajo",
  "mood.option.okay": "Normal",
  "mood.option.good": "Bien",
  "mood.option.light": "Ligero",
  "energy.option.drained": "Baja",
  "energy.option.steady": "Estable",
  "energy.option.energized": "Alta",
  "sleep.option.1": "Difícil",
  "sleep.option.2": "Mala",
  "sleep.option.3": "Regular",
  "sleep.option.4": "Buena",
  "sleep.option.5": "Reparadora",
  "activityTag.work": "Trabajo",
  "activityTag.family": "Familia",
  "activityTag.friends": "Amistades",
  "activityTag.exercise": "Ejercicio",
  "activityTag.outdoors": "Aire libre",
  "activityTag.rest": "Descanso",
  "activityTag.creative": "Creatividad",
  "activityTag.health": "Salud",
  "activityTag.money": "Dinero",
  "activityTag.travel": "Viaje",

  // -------------------------------------- reminder notifications (fix 22)
  // El texto del sistema (cuerpo de la notificación, nombre del canal de
  // Android) se resuelve por catálogo para que un dispositivo en español
  // lea un recordatorio en español.
  "notify.reminderBody": "Un momento tranquilo para escribir, cuando le venga bien.",
  "notify.channelName": "Recordatorios del diario",
  // El empuje de los cuestionarios (2026-09-27): una invitación, nunca una
  // deuda — sin "atrasado", sin rachas, nada que sentir mal (el mismo
  // contrato de mensajería segura que el recordatorio diario).
  "notify.measureReminderBody": "Un momento tranquilo para un cuestionario de bienestar, cuando le venga bien.",

  // ---------------------------------------------------------------- history
  "history.snapshotReload": "Su diario cambió mientras se cargaban las entradas más antiguas. Recargando el historial más reciente desde el principio.",
  "history.revisionConflict": "Su diario cambió mientras se cargaba. Inténtelo de nuevo para recargar el historial más reciente.",
  "history.entryDeleted": "Entrada eliminada",
  "history.entryWord": "entrada",
  "history.entryWordPlural": "entradas",
  "history.loadOlderFailedTitle": "No se pudieron cargar las entradas más antiguas",
  "history.needsConnectionTitle": "Se necesita conexión",
  "history.deleteOfflineBody": "Eliminar quita la entrada del servidor, así que no puede hacerse sin conexión. Conéctese e inténtelo de nuevo — no se cambió nada.",
  "history.couldNotDeleteTitle": "No se pudo eliminar",
  "history.deleteConfirmTitle": "¿Eliminar esta entrada?",
  "history.deleteConfirmBody": "Esto quita la entrada de su diario en todos los dispositivos. No se puede deshacer.",
  "history.finalConfirmBody": "Eliminar es permanente — no existe ninguna copia desde la que restaurar.",
  "history.sessionDamagedBody": "Falta el id de la cuenta — inicie sesión de nuevo. Su texto sigue en pantalla.",
  "history.tooLongTitle": "Entrada demasiado larga",
  "history.tooLongBody": "Las entradas están limitadas a {max} caracteres.",
  "history.updateOfflineBody": "Actualizar necesita conexión. Su entrada original y este texto siguen a salvo; inténtelo de nuevo cuando haya conexión.",
  "history.couldNotUpdateTitle": "No se pudo actualizar",
  "history.updateFailedBody": "{reason} Su entrada original no cambió y este texto sigue en pantalla.",
  "history.updated": "Actualizado ✓",
  "history.editA11y": "Editar entrada",
  "history.charCount": "{current} / {max}",
  "history.saveChanges": "Guardar cambios",
  "history.editThisEntry": "Editar esta entrada",
  "history.deleteThisEntry": "Eliminar esta entrada",
  "history.backToHistory": "Volver al historial",
  "history.tryAgainA11y": "Intentar cargar su historial de nuevo",
  "history.offlineBody": "Su historial se carga cuando hay conexión; la escritura de hoy siempre funciona sin conexión.",
  "history.emptyBody": "Aún no hay entradas. Lo que escriba cada día se reunirá aquí — descifrado solo en este dispositivo.",
  "history.searchPlaceholder": "Buscar en sus entradas",
  "history.moodBadgeA11y": "Ánimo: {label}",
  "history.matchOne": "{count} entrada coincide",
  "history.matchMany": "{count} entradas coinciden",
  "history.filterDay": " · {date}",
  "history.filterSearch": " · búsqueda",
  "history.filterLoaded": " · solo el historial cargado",
  "history.entryA11y": "Entrada del {date}",
  "history.showOlder": "Mostrar entradas más antiguas ({count} más)",
  "history.loadingOlder": "Cargando entradas más antiguas…",
  "history.loadOlder": "Cargar entradas más antiguas",
  "history.loadOlderA11y": "Cargar entradas cifradas más antiguas del diario",
  "history.limitReached": "Se cargaron las {rows} entradas más recientes. Para leer algo anterior, ve a ese mes en el calendario: cada mes se carga al momento.",
  "history.monthLoaded": "{count} entradas de ese mes ya están en tu historial.",
  "history.monthEmpty": "No hay entradas en ese mes.",
  "history.monthLoadFailed": "No se pudo cargar ese mes: revisa tu conexión e inténtalo de nuevo.",
  "history.noMatchSearch": "Nada coincide con esa búsqueda.",
  "history.noMatchDay": "Nada coincide con ese día.",
  "history.unreadableOne": "{count} entrada no se pudo leer en este dispositivo.",
  "history.unreadableMany": "{count} entradas no se pudieron leer en este dispositivo.",
  "history.rekeyedElsewhere": "Ninguna entrada se pudo descifrar — su diario fue recifrado tras un cambio de contraseña en otro dispositivo. Cierre sesión y vuelva a iniciarla con su nueva contraseña.",
  "history.conflictTitle": "Esta entrada cambió en otro dispositivo",
  // 2026-09-26 audit LOW: "Su versión" en ambos lados era ambiguo — el
  // diálogo no distinguía la versión del otro dispositivo de la nueva local.
  "history.conflictBody": "La versión guardada en el otro dispositivo:\n{theirs}\n\nSu versión nueva:\n{yours}\n\n¿Reemplazar la versión del otro dispositivo con la suya?",
  // 2026-09-26 audit M-M3: ambos lados del diálogo se recortan a ~300
  // caracteres; el sufijo declara la longitud TOTAL para que el recorte sea
  // explícito antes de la opción destructiva de reemplazo.
  "history.conflictSnippetSuffix": "… ({count} caracteres en total)",
  "history.conflictKeepTheirs": "Conservar la otra",
  "history.conflictOverwrite": "Reemplazar con la mía",
  "history.deletedElsewhereTitle": "Eliminada en otro dispositivo",
  "history.deletedElsewhereBody": "Esta entrada fue eliminada desde otro dispositivo, por lo que su edición no se guardó.",
  // Auditoría 2026-09-28 (MEDIA): el botón atrás o Cancelar con ediciones
  // sin guardar pide confirmación en lugar de descartarlas en silencio.
  "history.discardEditTitle": "¿Descartar sus cambios?",
  "history.discardEditBody": "Los cambios que hizo en esta entrada aún no se han guardado.",
  "history.discardEditConfirm": "Descartar cambios",
  "history.discardEditCancel": "Seguir editando",

  // --------------------------------------------------------------- insights
  "insights.tryAgainA11y": "Intentar cargar sus patrones de nuevo",
  "insights.baselineTitle": "Siga escribiendo — {count} {unit} para sus patrones",
  "insights.baselineBody":
    "La espera es deliberada: con menos de {days} días de entradas, cualquier \"idea\" sería una suposición disfrazada de hallazgo. Los patrones reales necesitan historia real.",
  "insights.moodMonthDevice": "Su ánimo, este mes (se queda en este dispositivo):",
  "insights.nothingSolidTitle": "Aún nada firme",
  "insights.allMutedBody": "Todos los patrones actuales están silenciados — reactive uno abajo, o siga escribiendo.",
  "insights.noEvidenceBody": "Ningún patrón recurrente tiene suficiente evidencia. Siga escribiendo.",
  "insights.moodMonth": "Su ánimo, este mes",
  "insights.moodMonthNote": "Registrado en este dispositivo con su registro diario.",
  "insights.mutedNote": "Silenciado — oculto aquí ahora, y fuera de sus preguntas tras su próxima actualización.",
  "insights.unmutedNote": "Reactivado — vuelve con su próxima actualización de preguntas.",
  "insights.sensitiveBody": "Un pensamiento difícil ha estado volviendo a lo largo de distintos días.",
  "insights.supportResources": "Recursos de apoyo",
  "insights.supportResourcesA11y": "Recursos de apoyo — ayuda en crisis",
  "insights.newFlag": " · nuevo",
  "insights.meta": "{count} menciones · densidad de evidencia {density}%",
  "insights.hideEvidence": "Ocultar la evidencia",
  "insights.whySeeing": "¿Por qué veo esto?",
  "insights.whySeeingA11y": "¿Por qué veo esto? Evidencia de este patrón",
  "insights.muteA11y": "Silenciar este patrón — {label}",
  "insights.muteLabel": "Ya no me representa — silenciar",
  "insights.hideTech": "Ocultar detalles técnicos",
  "insights.techDetails": "Detalles técnicos",
  "insights.techDetailsA11y": "Detalles técnicos — las estadísticas completas",
  "insights.evidenceFootnote1": "Los patrones pueden aparecer por casualidad de vez en cuando — por eso mostramos la evidencia.",
  "insights.evidenceFootnote2": "Una observación sobre sus propios datos — no un diagnóstico ni un consejo.",
  "insights.showMutedA11y": "Mostrar patrones silenciados, {count} en total",
  "insights.hideMutedA11y": "Ocultar patrones silenciados",
  "insights.mutedCountHide": "Ocultar silenciados ({count})",
  "insights.mutedCountShow": "Mostrar silenciados ({count})",
  "insights.mutedNoteBody": "Los patrones silenciados quedan fuera de sus preguntas. Reactivarlos los trae de vuelta.",
  "insights.unmute": "Reactivar",
  "insights.unmuteA11y": "Reactivar este patrón — {label}",
  "insights.footnote": "Son observaciones, no consejos ni diagnósticos. Usted decide qué significan.",
  "insights.unknownPhase": "el servidor reportó una fase de patrones desconocida",
  "insights.state.emerging": "evidencia temprana",
  "insights.state.confirmed": "visto con consistencia",
  "insights.state.fading": "desvaneciéndose",
  "insights.state.observed": "observado",
  "insights.kind.temporal": "HORARIO",
  "insights.kind.mood_correlation": "VÍNCULO CON EL ÁNIMO",
  "insights.kind.link": "VÍNCULO AL DÍA SIGUIENTE",
  "insights.kind.inertia": "ARRASTRE",
  "insights.kind.energy_inertia": "ARRASTRE DE ENERGÍA",
  "insights.kind.pa_inertia": "ARRASTRE POSITIVO",
  "insights.kind.na_inertia": "ARRASTRE NEGATIVO",
  "insights.kind.energy_mood_coupling": "ENERGÍA Y ÁNIMO",
  "insights.kind.instability": "ALTIBAJOS",
  "insights.kind.recurring_phrase": "FRASE REPETIDA",
  "insights.kind.rumination": "PREOCUPACIÓN REPETIDA",
  "insights.kind.topic": "TEMA",
  "insights.kind.mood_shift": "TENDENCIA DEL ÁNIMO",
  "insights.kind.avoidance": "SILENCIO DESPUÉS",
  "insights.kind.cadence": "RITMO",
  "insights.kind.sense_making": "CONSTRUCCIÓN DE SENTIDO",
  "insights.kind.activity_diversity": "VARIEDAD DE ACTIVIDADES",
  "insights.kind.fallback": "PATRÓN",
  // M-36: registro "usted" en todo el catálogo (antes estos dos usaban "tu").
  "insights.languageTitle": "Sobre el idioma de su diario",
  "insights.languageBody": "El an\u00e1lisis de patrones funciona en ingl\u00e9s y espa\u00f1ol. En otro idioma, sus entradas y registros se guardan y sincronizan igual: el motor prefiere no adivinar. El soporte de idiomas crece con cada l\u00e9xico cuidadosamente construido.",
  "insights.effect.verySmall": "una diferencia muy pequeña",
  "insights.effect.small": "una diferencia pequeña",
  "insights.effect.medium": "una diferencia mediana",
  "insights.effect.large": "una diferencia grande",
  "insights.words.higher": "más alto",
  "insights.words.lower": "más bajo",
  "insights.theme.work": "el trabajo",
  "insights.theme.sleep": "el sueño",
  "insights.theme.social": "la vida social",
  "insights.theme.family": "la familia",
  "insights.theme.health": "la salud",
  "insights.theme.money": "el dinero",
  "insights.theme.study": "el estudio",
  "insights.theme.food": "la comida",
  "insights.theme.weather": "el clima",
  "insights.words.narrowed": "se estrechó",
  "insights.words.widened": "se amplió",
  "insights.method.temporal":
    "Concentración en días de la semana probada contra su propio calendario de escritura (binomial exacta, corregida por comparaciones múltiples).",
  "insights.method.mood_correlation":
    "Dentro de la persona: días con este tema frente a su propia línea base de ánimo en las mismas semanas (t de Welch + umbral de tamaño del efecto).",
  "insights.method.link":
    "Asociación al día siguiente frente a su propia línea base — la forma del vínculo mejor replicada en los estudios de registro diario (p. ej., sueño → ánimo del día siguiente).",
  "insights.method.inertia":
    "Arrastre del ánimo de un día al otro (autocorrelación) comparado con su propia norma anterior — una dinámica ligada al bienestar en metaanálisis.",
  "insights.method.energy_inertia":
    "Arrastre de la energía de un día al otro (autocorrelación) a partir de sus propias elecciones de energía, comparado con su propia norma anterior.",
  "insights.method.pa_inertia":
    "Arrastre de las palabras POSITIVAS de lo que escribe, comparado con su propia norma anterior (el afecto positivo y el negativo son corrientes separables).",
  "insights.method.na_inertia":
    "Arrastre de las palabras NEGATIVAS de lo que escribe, comparado con su propia norma anterior (el afecto positivo y el negativo son corrientes separables).",
  "insights.method.energy_mood_coupling":
    "Qué tan de cerca se mueven juntos sus registros de energía y el ánimo de sus entradas (dentro de la persona), comparado con su propia norma anterior.",
  "insights.method.sense_making":
    "La proporción de palabras causales y de descubrimiento ('porque', 'me doy cuenta') en sus entradas, comparada con su propia norma anterior — un cambio ligado a la construcción de sentido en la literatura sobre escritura expresiva.",
  "insights.method.activity_diversity":
    "La variedad de sus etiquetas de actividad por semana (entropía de Shannon), comparada con sus propias semanas anteriores.",
  "insights.method.instability": "La dispersión de su ánimo diario comparada con su propia norma anterior.",
  "insights.method.mood_shift": "Un gráfico de control sobre su ánimo diario frente a su línea base personal — hecho justamente para este uso.",
  "insights.method.recurring_phrase": "Agrupamiento de frases casi duplicadas a lo largo de días separados.",
  "insights.method.rumination":
    "Un pensamiento negativo que vuelve. El pensamiento negativo repetitivo es un patrón bien estudiado; esto agrupa frases negativas casi idénticas.",
  "insights.method.topic":
    "Un tema recurrente descubierto a partir de sus propias palabras — no de ninguna lista fija. Los temas en aumento se prueban contra sus propias entradas anteriores (binomial exacta).",
  "insights.method.avoidance":
    "Los días con este tema van seguidos más a menudo de un día en silencio que su propio patrón habitual (binomial exacta contra su tasa base, corregida por comparaciones múltiples).",
  "insights.method.cadence":
    "La regularidad de su ritmo de escritura comparada con su propia norma anterior (dispersión de los intervalos entre días de escritura).",
  "insights.ev.window": "Ventana de evidencia",
  "insights.ev.windowValue": "{from} → {to}",
  "insights.ev.basedOn": "Basado en",
  "insights.ev.basedOnValue": "{count} entradas en su ventana de análisis",
  "insights.ev.concentration": "Concentración",
  // 2026-09-26 audit LOW: "cayeron en {day}" con un día de la semana solo
  // es gramatical con el artículo — "caían los {day}".
  "insights.ev.concentrationValue": "{share}% de estas menciones caían los {day} — su línea base para los {day} es {baseline}%",
  "insights.ev.moodDiff": "Diferencia de ánimo",
  "insights.ev.moodDiffValue": "las entradas suenan {direction} que su propia norma, por una diferencia de {amount}",
  "insights.ev.size": "Tamaño de la diferencia",
  "insights.ev.dayAfter": "Día siguiente",
  "insights.ev.dayAfterValue": "~{lag} día después — visto en {after} días así frente a {other} otros",
  "insights.ev.carryover": "Arrastre",
  "insights.ev.carryoverMood": "el ánimo ha venido arrastrándose con más fuerza de lo que solía hacerlo en su caso",
  "insights.ev.carryoverEnergy": "su energía ha venido arrastrándose con más fuerza de lo que solía hacerlo en su caso",
  "insights.ev.carryoverPositive": "sus sentimientos positivos han venido arrastrándose con más fuerza de lo que solían en su caso",
  "insights.ev.carryoverNegative": "sus sentimientos negativos han venido arrastrándose con más fuerza de lo que solían en su caso",
  "insights.ev.tracking": "Movimiento conjunto",
  "insights.ev.trackingValue": "su energía y su ánimo han venido moviéndose más al unísono que antes",
  "insights.ev.senseWords": "Palabras de sentido",
  "insights.ev.senseWordsValue": "{recent} por cada 100 palabras últimamente, frente a sus {earlier} anteriores",
  "insights.ev.activityVariety": "Variedad de actividades",
  "insights.ev.activityVarietyValue": "{direction} — {recent} bits por semana últimamente, frente a sus {earlier} anteriores",
  "insights.ev.swings": "Altibajos",
  "insights.ev.swingsValue": "su ánimo diario se ha repartido en un rango más amplio que antes",
  "insights.ev.share": "Proporción de entradas",
  "insights.ev.shareValue": "{share}% ({entries} entradas, {mentions} menciones)",
  "insights.ev.earlierRecent": "Antes → reciente",
  "insights.ev.earlierRecentValue": "{earlier}% → {recent}%",
  "insights.ev.returning": "Presente durante",
  "insights.ev.returningValue": "visto en {days} días distintos a lo largo de {span} días",
  "insights.ev.tone": "Tono",
  "insights.ev.toneValue": "el pensamiento se lee negativo",
  "insights.ev.shift": "Cambio",
  "insights.ev.shiftValue": "{sign}{amount} frente a su línea base de {baseline}",
  "insights.ev.silentDays": "Días en silencio después",
  "insights.ev.silentDaysValue": "{silences} de {observed} de esos días (su tasa habitual de días en silencio es {rate}%)",
  "insights.ev.rhythm": "Ritmo",
  "insights.ev.rhythmValue": "dispersión de intervalos {recent} frente a sus {earlier} días anteriores",
  "insights.ev.method": "Método",
  "insights.tech.significance": "Significancia",
  "insights.tech.significanceValue": "p = {value} (corregido por ejecutar muchas pruebas)",
  "insights.tech.cohensD": "d de Cohen",
  "insights.tech.negativity": "Puntaje de negatividad",
  "insights.tech.absolutist": "Densidad de palabras absolutistas",
  "insights.tech.absolutistValue": "{value} por cada 100 palabras",
  "insights.tech.carryover": "Arrastre, reciente vs anterior",
  "insights.tech.coupling": "Acoplamiento, reciente vs anterior",
  "insights.tech.spread": "Dispersión, reciente vs anterior",
  "insights.tech.pairValue": "{recent} vs {earlier}",
  // 2026-09-26 audit LOW: "en {day}" con un día de la semana suelta carece
  // de artículo; la construcción gramatical es "los {day}".
  "insights.desc.temporal": "Ha mencionado '{label}' {count} veces, la mayoría de las veces los {day}.",
  "insights.desc.sameDay": "el mismo día",
  "insights.desc.certainDay": "ciertos días",
  "insights.desc.moodCorrelation": "Sus entradas se leen {direction} en los días en que aparece '{label}' (cambio de ánimo de {shift}).",
  "insights.desc.link": "El día después de que aparece '{label}', sus entradas se leen {direction} de lo habitual en su caso.",
  "insights.desc.inertia": "Su ánimo ha venido arrastrándose de un día al otro más de lo habitual en su caso.",
  "insights.desc.energyInertia": "Su energía ha venido arrastrándose de un día al otro más de lo habitual en su caso.",
  "insights.desc.paInertia": "Sus sentimientos positivos han venido arrastrándose de un día al otro más de lo habitual en su caso.",
  "insights.desc.naInertia": "Sus sentimientos negativos han venido arrastrándose de un día al otro más de lo habitual en su caso.",
  "insights.desc.coupling": "Su energía y su ánimo han venido moviéndose juntos más estrechamente de lo habitual en su caso.",
  "insights.desc.senseMaking": "Lo que escribe se ha apoyado más que antes en palabras de sentido — como 'porque' y 'me doy cuenta'.",
  "insights.desc.activityNarrowed": "La variedad de sus actividades etiquetadas se ha estrechado en comparación con lo habitual en su caso.",
  "insights.desc.activityWidened": "La variedad de sus actividades etiquetadas se ha ampliado en comparación con lo habitual en su caso.",
  "insights.desc.instability": "Su ánimo diario ha oscilado más ampliamente de lo habitual en su caso estas últimas semanas.",
  "insights.desc.recurringPhrase": "La frase \"{label}\" sigue volviendo — {count} veces hasta ahora.",
  "insights.desc.rumination": "El pensamiento \"{label}\" sigue volviendo a lo largo de distintos días — {count} veces hasta ahora.",
  "insights.desc.topicRising": "'{label}' ha estado ocupando más espacio en lo que escribe últimamente{share}.",
  "insights.desc.topicSteady": "'{label}' es una presencia constante en lo que escribe{share}.",
  "insights.desc.topicShare": " ({share}% de las entradas)",
  "insights.desc.moodShift": "Últimamente sus entradas han sonado {direction} que su línea base habitual (un cambio de {shift}).",
  "insights.desc.sleepLink": "El día después de una noche que valoró como más difícil de lo habitual en su caso, sus entradas se leen {direction} de lo habitual.",
  "insights.desc.sleepCorrelation": "En las noches que valoró como más difíciles de lo habitual en su caso, sus entradas se leen {direction} ese mismo día.",
  "insights.desc.sleepTemporal": "Sus noches más difíciles (según sus propias valoraciones) caen más a menudo en {day}.",
  "insights.desc.avoidance": "El día después de que aparece '{label}', suele no escribir{share}.",
  "insights.desc.avoidanceShare": " ({share}% de esos días)",
  "insights.desc.cadence": "Su ritmo de escritura ha sido menos regular de lo que solía ser en su caso — tramos más largos de silencio entre días de escritura.",
  "insights.desc.tagCorrelation": "Sus entradas se leen {direction} en los días en que etiqueta '{label}'.",
  "insights.desc.tagLink": "El día después de etiquetar '{label}', sus entradas se leen {direction} de lo habitual en su caso.",
  "insights.desc.tagTemporal": "Etiqueta '{label}' más a menudo en {day}.",
  "insights.desc.fallback": "'{label}' apareció {count} veces.",
  "insights.spark.summary": "Tendencia del ánimo: {trend} a lo largo de {count} {unit}, lo último {latest}",
  "insights.spark.steady": "estable",
  "insights.spark.rising": "en aumento",
  "insights.spark.falling": "a la baja",
  "insights.spark.positive": "positivo",
  "insights.spark.negative": "negativo",
  "insights.spark.neutral": "neutro",

  // --------------------------------------------------------------- question
  "question.loadFailedTitle": "No se pudo cargar la pregunta",
  "question.sessionMismatch": "la sesión y las llaves desbloqueadas no coinciden — inicie sesión de nuevo",
  "question.noticedMore": "Anotado — preguntas así aparecerán más a menudo.",
  "question.noticedLess": "Anotado — esta dará un paso atrás.",
  "question.feedbackSaveFailed": "Su respuesta se queda en este dispositivo; no se pudo guardar en este momento.",
  "question.noEvidenceYet": "Ningún patrón recurrente tiene aún suficiente evidencia — siga escribiendo.",
  "question.keyShipTitle": "Su llave, un momento",
  "question.keyShipBody":
    "Para calcular sus patrones, su llave de cifrado se envía al servidor una sola vez — se mantiene en memoria por un máximo de 5 minutos y luego se destruye. Nunca se guarda, y solo se envía cuando usted lo pide desde esta pantalla.",
  "question.today": "Hoy",
  "question.baselineCaption": "Por ahora, una pregunta al día. Después de {days} días de escritura, sus preguntas empiezan a salir de SUS propios patrones.",
  "question.dayOf": "Día {active} de {total}",
  "question.writeAbout": "Escribir sobre esto",
  "question.writeAboutA11y": "Escribir sobre esta pregunta",
  "question.oneADay": "Una pregunta al día. Sin consejos — solo algo para reflexionar.",
  "question.resonated": "Resonó conmigo",
  "question.resonatedA11y": "Esta pregunta resonó conmigo",
  "question.notMe": "No soy yo",
  "question.notMeA11y": "Esta pregunta no me representa",
  "question.refresh": "Actualizar",
  "question.showToday": "Mostrar la pregunta de hoy",
  "question.captionBaseline": "La pregunta de hoy viene de un pequeño conjunto integrado — nada sale de este dispositivo por ella.",
  "question.captionOffline": "No se puede conectar con el servidor ahora mismo — aquí tiene una pregunta general para hoy.",
  "question.captionInsight": "Calcular su pregunta puede enviar su llave de cifrado al servidor una vez — se mantiene en memoria por un máximo de 5 minutos, nunca se guarda.",
  "question.accountMissingPlain": "Falta el id de la cuenta — inicie sesión de nuevo.",

  // --------------------------------------------------------------- settings
  "settings.reminderMorning": "Mañana 9:00",
  "settings.reminderMidday": "Mediodía 12:00",
  "settings.reminderEvening": "Noche 20:00",
  "settings.invalidUrlTitle": "URL no válida",
  "settings.invalidUrlBody": "Escriba una URL completa como https://su-servidor:8000",
  "settings.couldNotSaveServerTitle": "No se pudo guardar el servidor",
  "settings.serverSavedTitle": "Guardado",
  "settings.serverSavedBody": "URL del servidor actualizada. Cambiar el origen del servidor cierra la sesión en este dispositivo para protegerla.",
  "settings.signInRequiredTitle": "Hace falta iniciar sesión",
  "settings.signInRequiredBody": "Inicie sesión de nuevo antes de reintentar las entradas guardadas.",
  "settings.recoveredTitle": "Entradas recuperadas",
  "settings.recoveredMoved": "{count} {unit} volvieron a la cola de sincronización — {rest}",
  "settings.recoveredUploadNext": "se subirán en la próxima sincronización.",
  "settings.recoveredStillWaiting": "{count} siguen esperando.",
  "settings.recoveredNone": "Aún no se pudo mover nada — las entradas siguen guardadas de forma segura en este dispositivo.",
  "settings.couldNotRetryTitle": "No se pudo reintentar",
  "settings.couldNotRetryBody": "Las entradas guardadas siguen a salvo en este dispositivo.",
  "settings.deletedTitle": "Eliminado",
  "settings.deletedBody": "Su cuenta y sus datos fueron eliminados del servidor. Si algo no se pudo limpiar en este dispositivo, reinstalar la app quita los restos.",
  "settings.deleteFailedTitle": "Error al eliminar",
  "settings.deleteFailedSession": "La sesión expiró — vuelva a desbloquear. No se eliminó nada.",
  "settings.exportTitle": "Exportación no disponible en esta versión",
  "settings.exportBody":
    "Para proteger los diarios grandes, esta app necesita su componente verificado de exportación segura de archivos antes de poder crear una exportación. Sus entradas siguen a salvo en el servidor y en este dispositivo.",
  "settings.reminderSaveFailedTitle": "No se pudo guardar",
  "settings.reminderSaveFailedBody": "La preferencia de recordatorio no se guardó — inténtelo de nuevo.",
  "settings.reminderNotScheduledTitle": "Recordatorio no programado",
  "settings.reminderNotScheduledBody": "Las notificaciones están desactivadas para esta app en los ajustes del dispositivo — el recordatorio comenzará en cuanto se permitan.",
  "settings.healthMirrorSaveFailedTitle": "No se pudo guardar",
  "settings.healthMirrorSaveFailedBody": "La preferencia de Salud no se guardó — inténtelo de nuevo.",
  "settings.healthMirrorDeniedTitle": "Acceso a Salud no concedido",
  "settings.healthMirrorDeniedBody":
    "La app Salud no ha concedido el permiso de escritura. Puede cambiarlo en la privacidad de la app Salud; la preferencia queda guardada y nada más cambia.",
  "settings.bioOffFailedTitle": "No se pudo desactivar",
  "settings.bioOffFailedBody": "Inténtelo de nuevo — su contraseña sigue funcionando de cualquier forma.",
  "settings.bioTitle": "¿Usar el desbloqueo biométrico?",
  "settings.bioBody":
    "Su llave de datos se guardará en este dispositivo, protegida con su huella o su rostro. Su contraseña seguirá funcionando exactamente igual que antes, y desactivar esto quita la llave guardada.",
  "settings.bioEnable": "Activar",
  "settings.bioOnFailedTitle": "No se pudo activar",
  "settings.bioOnFailedBody": "No se guardó nada — su contraseña sigue funcionando.",
  "settings.deleteAllTitle": "¿Eliminar todo?",
  "settings.deleteAllBody":
    "Todas las entradas, los patrones y su cuenta se eliminarán definitivamente del servidor. Su cola cifrada local también se borra. Esto no se puede deshacer. Se le pedirá su contraseña.",
  "settings.deleteAllFinalBody": "Eliminar es irreversible. A continuación se le pedirá su contraseña.",
  "settings.continueToPassword": "Continuar a la contraseña",
  "settings.rejectedOne": "{count} entrada no pudo sincronizarse y se guardó a salvo en este dispositivo.",
  "settings.rejectedMany": "{count} entradas no pudieron sincronizarse y se guardaron a salvo en este dispositivo.",
  "settings.retrySync": "Intentar sincronizarlas de nuevo",
  "settings.retrySyncA11y": "Intentar sincronizar de nuevo las entradas recuperadas",
  "settings.quarantinedNote": "Una pieza dañada de la cola sin conexión se apartó en lugar de eliminarse. Las entradas nuevas se sincronizan con normalidad.",
  "settings.legacyTitle": "Unas entradas sin conexión anteriores necesitan recuperación",
  "settings.legacyBody":
    "Esta actualización protegió entradas cifradas no enviadas de que llegaran al servidor equivocado. Siguen en este dispositivo, pero no pueden asignarse de forma segura automáticamente; contacte con soporte antes de borrar los datos de la app.",
  "settings.llmLabel": "Análisis con IA de terceros",
  "settings.llmBody": "Permitir enviar sus entradas (descifradas) a un servicio de IA externo para el análisis de patrones. Desactivado por defecto; se necesita su contraseña para cambiarlo.",
  "settings.llmA11y": "Permitir el análisis con IA de terceros",
  "settings.reauthDeleteTitle": "Escriba su contraseña para eliminar todo",
  "settings.reauthBioTitle": "Escriba su contraseña para activar el desbloqueo biométrico",
  "settings.changePasswordLabel": "Cambiar contraseña",
  "settings.changePasswordCancel": "Cerrar cambiar contraseña",
  "settings.changePasswordTitle": "Cambie su contraseña",
  "settings.changePasswordBody":
    "Esto rota su credencial de acceso Y vuelve a cifrar su diario con una clave nueva: es el paso de recuperación si su contraseña o clave se expuso alguna vez. Todos los dispositivos cerrarán sesión; los permisos de compartir activos se re-envuelven automáticamente.",
  // Copia v2 (2026-09-26): las cuentas con sobre de llave cambian la
  // contraseña SIN volver a cifrar nada — la descripción honesta de O(1).
  "settings.changePasswordTitleV2": "Cambie su contraseña",
  "settings.changePasswordBodyV2":
    "Esto cambia la contraseña que bloquea su clave de cifrado. Su diario no se vuelve a cifrar — queda exactamente como está, y compartir con su terapeuta sigue funcionando sin cambios. Todos los dispositivos cerrarán sesión.",
  "settings.newPasswordPlaceholder": "Contraseña nueva (12+ caracteres)",
  "settings.newPasswordA11y": "Contraseña nueva",
  "settings.changePasswordButton": "Rotar claves e iniciar sesión de nuevo",
  "settings.changePasswordButtonV2": "Cambiar contraseña e iniciar sesión de nuevo",
  "settings.rotateWorking": "Rotando…",
  "settings.rotateSuccessTitle": "Contraseña cambiada",
  "settings.rotateSuccessBody":
    "Su diario ahora está cifrado con su nueva contraseña. Inicie sesión de nuevo en este dispositivo y en cualquier otro que use.",
  "settings.rotateSuccessBodyV2":
    "Su contraseña ahora abre una copia recién envuelta de su clave de cifrado; la clave en sí no cambió, así que su diario y sus permisos de compartir quedaron tal como estaban. Inicie sesión de nuevo en este dispositivo y en cualquier otro que use.",
  "settings.rotateFailedTitle": "No se pudo cambiar la contraseña",
  "settings.rotateWrongOld": "La contraseña actual no fue aceptada. No se cambió nada.",
  // Auditoría independiente 27/09/2026 (P2): la cola sin conexión está sellada
  // con la llave de datos ANTIGUA; rotar antes de vaciarla dejaría huérfanas
  // todas las entradas en cola. La rotación se aborta antes de cualquier paso
  // en el servidor con este mensaje honesto.
  "settings.rotateQueueBlocked":
    "Aún hay entradas esperando para subirse desde este dispositivo, selladas con su contraseña actual — cambiarla ahora las dejaría ilegibles. Guárdelas primero (mantenga la aplicación abierta con conexión hasta que la cola se vacíe) y vuelva a intentarlo.",
  "settings.rotateRewrapFailed":
    "Estos permisos de compartir no pudieron re-envolverse y deben emparejarse de nuevo con el código del terapeuta: {names}",
  // --- Mejora v1 → v2 del sobre de llaves (2026-09-26) --------------------
  // Alcance honesto: nada se vuelve a cifrar, la clave de datos no cambia;
  // el beneficio es que cambiar la contraseña pasa a ser instantáneo. La
  // acción envía la clave de datos ACTUAL al servidor (dentro del sobre
  // protegido por contraseña), por eso va detrás de la tarjeta de contraseña.
  "settings.upgradeTitle": "Mejorar la protección de llaves",
  "settings.upgradeBody":
    "Un cambio único en cómo su contraseña protege su diario: hoy su contraseña deriva directamente su clave de cifrado, así que cambiarla vuelve a cifrar todo. Tras la mejora, una clave aleatoria aparte cifra su diario y su contraseña la bloquea — los cambios futuros de contraseña serán instantáneos y su diario guardado no cambia en nada. Esto pide su contraseña y toma un momento.",
  "settings.upgradeButton": "Mejorar ahora",
  "settings.reauthUpgradeTitle": "Escriba su contraseña para mejorar la protección de llaves",
  "settings.upgradeSuccessTitle": "Protección de llaves mejorada",
  "settings.upgradeSuccessBody":
    "Su diario no cambió y se abre igual que antes. A partir de ahora, cambiar su contraseña no vuelve a cifrarlo.",
  "settings.upgradeAlreadyTitle": "Ya está mejorada",
  "settings.upgradeAlreadyBody":
    "Esta cuenta ya usa la protección de llaves más nueva. No había nada que cambiar.",
  "settings.upgradeFailedTitle": "No se pudo mejorar la protección de llaves",
  "settings.upgradeKeyMismatchBody":
    "La clave de cifrado de este dispositivo no coincide con los datos guardados en el servidor, así que no se cambió nada. Bloquee la app y desbloquéela de nuevo con su contraseña actual, y vuelva a intentarlo.",  "settings.reauthLlmTitle": "Escriba su contraseña para {action} el análisis con IA de terceros",
  "settings.enableWord": "activar",
  "settings.disableWord": "desactivar",
  "settings.languageTitle": "Idioma",
  "settings.languageDevice": "Idioma del dispositivo",
  "settings.languageEnglish": "English",
  "settings.languageSpanish": "Español",
  "settings.languageA11y": "Idioma de la app: {choice}",
  "settings.languageNote": "Se aplica de inmediato; las pantallas abiertas se actualizan en tu próxima visita.",
  "settings.appearanceLabel": "APARIENCIA",
  "settings.themeSystem": "Sistema",
  "settings.themeDark": "Oscuro",
  "settings.themeLight": "Claro",
  "settings.themeA11y": "Tema: {mode}",
  "settings.hapticsLabel": "Vibración suave al tocar y guardar",
  "settings.hapticsA11y": "Vibración",
  "settings.reminderLabel": "RECORDATORIO DIARIO",
  "settings.reminderNote": "Un empuje amable cada día — solo local, no se envía nada a ningún lugar.",
  "settings.remindMeLabel": "Recordarme escribir cada día",
  "settings.dailyReminderA11y": "Recordatorio diario",
  "settings.reminderTimeA11y": "Hora del recordatorio",
  "settings.reminderTimeOptionA11y": "Hora del recordatorio: {label}",
  "settings.reminderUnavailableNote": "{reason}. La preferencia se guarda y el aviso comenzará cuando esta versión incorpore las notificaciones.",
  // Auditoría 2026-09-28 (BAJA): claves que devuelven los módulos de
  // capacidades; la línea del motivo las resuelve con t() para localizarse.
  "settings.reasonNotifModule": "El módulo de notificaciones no está incluido en esta versión",
  // --- Recordatorios de cuestionarios (2026-09-27) ------------------------
  "settings.measureReminderLabel": "RECORDATORIOS DE CUESTIONARIOS",
  "settings.measureReminderRow": "Recordatorios de cuestionarios",
  "settings.measureReminderA11y": "Recordatorios de cuestionarios",
  "settings.measureReminderNote":
    "Un empuje amable para completar un cuestionario de bienestar cuando el último tenga más del intervalo que elija. Solo local — no se envía nada a ningún lugar.",
  "settings.measureIntervalA11y": "Intervalo de los cuestionarios",
  "settings.measureIntervalOptionA11y": "Intervalo de los cuestionarios: {label}",
  "settings.intervalWeeks": "{count} semanas",
  "settings.safetyPlanA11y": "Abrir su plan de seguridad",
  "settings.healthMirrorLabel": "APP DE SALUD",
  "settings.healthMirrorRow": "Reflejar mis registros de ánimo en la app Salud",
  "settings.healthMirrorA11y": "Reflejar mis registros de ánimo en la app Salud",
  "settings.healthMirrorNote":
    "Cuando está activado, cada registro de ánimo explícito también se escribe en la app Salud de este dispositivo. MindPattern nunca lee nada de Salud. Al desactivarlo se detienen las futuras escrituras; lo que Salud ya guardó se queda ahí.",
  "settings.healthMirrorUnavailableNote": "{reason}. La preferencia se guarda y el reflejo comenzará cuando esta versión incorpore el módulo de Salud.",
  "settings.reasonHealthModule": "El módulo de Salud no está incluido en esta versión",
  "settings.reasonHealthIOS18": "Estado de Ánimo de Apple Salud requiere iOS 18 o posterior",
  "settings.reasonHealthOldModule": "El módulo de Salud de esta versión es anterior a la función Estado de Ánimo",
  "settings.biometricLabel": "DESBLOQUEO BIOMÉTRICO",
  "settings.biometricRow": "Desbloquear con su rostro o su huella",
  "settings.biometricA11y": "Desbloqueo biométrico",
  "settings.biometricNote": "Su contraseña siempre seguirá funcionando.",
  "settings.shareWithTherapist": "Compartir con mi terapeuta",
  "settings.measures": "Cuestionarios de bienestar",
  "settings.measuresA11y": "Abrir el cuestionario de bienestar",
  "settings.shareWithTherapistA11y": "Compartir sus entradas y patrones con un terapeuta",
  "settings.sharingOffNote": "Compartir con terapeutas no está disponible en este servidor. Permanece desactivado hasta que se configure la inscripción verificada de profesionales.",
  "settings.sharingUnknownNote":
    "No se puede contactar al servidor para confirmar la disponibilidad de compartir con terapeutas — revise su conexión y vuelva a abrir Ajustes. No se comparte nada mientras tanto.",
  "settings.whyExport": "Por qué la exportación no está disponible",
  "settings.whyExportA11y": "Por qué la exportación no está disponible en esta versión",
  "settings.deleteAccount": "Eliminar mi cuenta y mis datos",
  "settings.signOut": "Cerrar sesión",
  "settings.aboutLabel": "Acerca de",
  "settings.aboutBody":
    "MindPattern {version}{server}. Todo lo que escribe se cifra en este dispositivo antes de salir de él. La única excepción — el análisis de patrones — corre en una sesión de un solo uso que usted mismo inicia. Sin consejos, sin diagnósticos, nunca.",
  "settings.serverVersionTag": " · servidor {version}",
  "settings.privacyPolicy": "Política de privacidad",
  "settings.privacyPolicyA11y": "Leer la política de privacidad",
  "settings.advancedLabel": "Avanzado",
  "settings.advancedNote": "Cambie esto solo si usa su propio servidor.",
  "settings.serverUrlPlaceholder": "https://su-servidor:8000",
  "settings.serverUrlA11y": "URL del servidor",
  "settings.saveServerUrl": "Guardar la URL del servidor",

  // --------------------------------------------------------- measures (M-16)
  "measures.intro":
    // 2026-09-26 audit LOW: nombrar los tres instrumentos (desde 2026-09-21
    // la pantalla ofrece también GAD-7 y PHQ-2, no solo PHQ-9).
    "Cuestionarios de bienestar estándar (PHQ-9, GAD-7 y PHQ-2), completados por usted. MindPattern guarda el puntaje cifrado y nunca lo interpreta — leerlo es tarea de su clínico, y se comparte solo mediante su consentimiento existente con el terapeuta.",
  "measures.offlineNote":
    "Su historial registrado necesita conexión para cargarse. Completar el cuestionario también la necesita — nada aquí funciona aún sin conexión.",
  "measures.loadFailed": "No se pudieron cargar sus cuestionarios.",
  "measures.historyTitle": "Sus puntajes registrados",
  "measures.emptyNote": "Aún nada registrado.",
  "measures.stemsHeader": "Durante las últimas 2 semanas, ¿con qué frecuencia le han molestado los siguientes problemas?",
  "measures.item9Note": " (pregunta de seguridad — el apoyo está siempre a un toque)",
  "measures.questionA11y": "Pregunta {index}",
  "measures.questionOptionA11y": "Pregunta {index}: {label}",
  "measures.recordButton": "Registrar este registro",
  "measures.backToSettings": "Volver a Ajustes",
  "measures.sessionDamagedTitle": "La sesión está dañada",
  "measures.sessionDamagedBody": "Falta el id de la cuenta — inicie sesión de nuevo.",
  "measures.lockedTitle": "Bloqueado",
  "measures.lockedBody": "Sus llaves están bloqueadas — desbloquéelas e inténtelo de nuevo.",
  "measures.recordedStatus": "Registrado — cifrado, como siempre.",
  "measures.alreadyRecorded": "Ya estaba registrado — actualizando.",
  "measures.notRecordedTitle": "No se registró",
  "measures.recordOfflineBody": "Registrar necesita conexión en este momento. Sus elecciones siguen en pantalla.",
  "measures.recordFailedBody": "No se pudo registrar en este momento. Sus elecciones siguen en pantalla.",
  "measures.crisisTitle": "Hay apoyo disponible",
  "measures.crisisBody":
    "Algo de lo que marcó suena pesado. Sea lo que esté cargando, no tiene que cargarlo en soledad — ayuda gratuita y confidencial está a un toque.",
  "measures.viewResources": "Ver recursos de apoyo",
  // PHQ-9: redacción estándar en español (instrumento de dominio público).
  "measures.phq9.item1": "Poco interés o placer en hacer las cosas",
  "measures.phq9.item2": "Sentirse desanimado/a, deprimido/a o sin esperanza",
  "measures.phq9.item3": "Dificultad para quedarse dormido/a, mantener el sueño o dormir demasiado",
  "measures.phq9.item4": "Sentirse cansado/a o tener poca energía",
  "measures.phq9.item5": "Poco apetito o comer en exceso",
  "measures.phq9.item6": "Sentirse mal consigo mismo/a — o sentir que es un fracaso o que ha decepcionado a su familia o a usted mismo/a",
  "measures.phq9.item7": "Dificultad para concentrarse en cosas, como leer o ver televisión",
  "measures.phq9.item8": "Moverse o hablar tan despacio que otras personas podrían notarlo — o estar tan inquieto/a que se ha estado moviendo mucho más que de costumbre",
  "measures.phq9.item9": "Pensar que estaría mejor muerto/a o en lastimarse de alguna manera",
  "measures.phq9.option0": "Para nada",
  "measures.phq9.option1": "Varios días",
  "measures.phq9.option2": "Más de la mitad de los días",
  "measures.phq9.option3": "Casi todos los días",
  // P3 (2026-09-21): etiquetas compartidas de la escala de frecuencia 0-3.
  "measures.option0": "Para nada",
  "measures.option1": "Varios días",
  "measures.option2": "Más de la mitad de los días",
  "measures.option3": "Casi todos los días",
  // P3 (2026-09-21): etiquetas del selector de instrumento.
  "measures.select.phq9": "PHQ-9 (depresión, 9 ítems)",
  "measures.select.gad7": "GAD-7 (ansiedad, 7 ítems)",
  "measures.select.phq2": "PHQ-2 (breve, 2 ítems)",
  // GAD-7 (Spitzer et al. 2006) — misma condición de dominio público y el
  // mismo encabezado "en las últimas 2 semanas" que el PHQ-9.
  "measures.gad7.item1": "Sentirse nervioso/a, ansioso/a o al límite",
  "measures.gad7.item2": "No poder dejar de preocuparse o controlar las preocupaciones",
  "measures.gad7.item3": "Preocuparse demasiado por diferentes cosas",
  "measures.gad7.item4": "Dificultad para relajarse",
  "measures.gad7.item5": "Estar tan inquieto/a que le cuesta quedarse sentado/a",
  "measures.gad7.item6": "Irritarse o molestarse con facilidad",
  "measures.gad7.item7": "Sentir miedo, como si algo terrible fuera a suceder",
  // PHQ-2: el núcleo de dos ítems del PHQ-9.
  "measures.phq2.item1": "Poco interés o placer en hacer las cosas",
  "measures.phq2.item2": "Sentirse desanimado/a, deprimido/a o sin esperanza",

  // ------------------------------------------- plan de seguridad (2026-09-27)
  // El plan de seguridad personal, local y cifrado (estructura inspirada en
  // Stanley-Brown; véase src/safetyPlan.ts). Copia DE SEGURIDAD CRÍTICA:
  // serena, clara, en primera persona donde el campo son las palabras del
  // usuario; los números y URL nunca cambian por idioma.
  "safetyplan.navTitle": "Mi plan de seguridad",
  "safetyplan.intro":
    "Un plan de seguridad es suyo: cómo se ven sus señales de alerta, qué le ayuda, a quién acudir. Se queda en este dispositivo, cifrado con su llave — nunca se envía a ningún lugar. Es una herramienta personal en la que apoyarse, no un sustituto de la ayuda profesional.",
  "safetyplan.field.warningSigns": "Mis señales de alerta",
  "safetyplan.hint.warningSigns": "Pensamientos, sentimientos, situaciones o comportamientos que le indican que comienza un momento difícil",
  "safetyplan.field.copingStrategies": "Cosas que puedo hacer para afrontarlo",
  "safetyplan.hint.copingStrategies": "Qué le ha calmado o dado estabilidad antes — en sus propias palabras",
  "safetyplan.field.peoplePlaces": "Personas y lugares que ayudan",
  "safetyplan.hint.peoplePlaces": "Nombres, números y lugares a los que puede acudir",
  "safetyplan.field.askForHelp": "A quién puedo pedir ayuda",
  "safetyplan.hint.askForHelp": "Personas en las que confía lo suficiente para decir «necesito ayuda»",
  "safetyplan.field.professionals": "Profesionales y servicios",
  "safetyplan.hint.professionals": "Su terapeuta, médico o clínica — las líneas de crisis de abajo ya están rellenas como punto de partida",
  "safetyplan.field.environmentSafer": "Hacer mi entorno más seguro",
  "safetyplan.hint.environmentSafer": "Qué podría mover, guardar bajo llave o apartar antes de un momento difícil",
  // El RELLENO inicial del campo de profesionales para un plan nuevo: las
  // líneas de crisis integradas de la app, tal cual la pantalla de crisis
  // (los números y URL son idénticos en todos los idiomas por diseño).
  "safetyplan.prefillProfessionals":
    "988 Suicide & Crisis Lifeline — llame o envíe un mensaje de texto al 988, o chatee en 988lifeline.org/chat\nCrisis Text Line — envíe HOME al 741741\nEmergencias (EE. UU.) — llame al 911\nFuera de EE. UU. — findahelpline.com",
  "safetyplan.save": "Guardar mi plan de seguridad",
  "safetyplan.saved": "Guardado — cifrado, como siempre.",
  "safetyplan.saveFailedTitle": "No se pudo guardar",
  "safetyplan.saveFailedBody": "Su plan sigue en pantalla tal como lo escribió — inténtelo de nuevo.",
  // Auditoría 2026-09-28 (MEDIA): volver atrás con ediciones sin guardar
  // pide confirmación en lugar de descartarlas en silencio.
  "safetyplan.discardTitle": "¿Descartar sus cambios?",
  "safetyplan.discardBody": "Los cambios de su plan de seguridad no se han guardado.",
  "safetyplan.discardConfirm": "Descartar cambios",
  "safetyplan.discardCancel": "Seguir editando",
  "safetyplan.lockedTitle": "Bloqueado",
  "safetyplan.lockedBody":
    "Su plan de seguridad está cifrado con su llave — desbloquéelo para leerlo o editarlo. Los recursos de crisis siguen a un toque abajo, como siempre.",

  // -------------------------------------------------------- therapist share
  "share.codeNotFoundTitle": "Código no encontrado",
  "share.codeNotFoundBody": "Revise el código con su terapeuta — expira 15 minutos después de que lo genere.",
  "share.lookupFailedTitle": "No se pudo buscar el código",
  "share.grantTitle": "¿Compartir con {name}?",
  // Divulgación de compartir v2 (auditoría H-14/M-25): el alcance nombra
  // cada clase derivada del paciente — entradas, patrones, cuestionarios
  // de bienestar (PHQ-9) y resúmenes de lista de casos.
  "share.grantBody":
    "Esa persona podrá leer cada entrada del diario, cada patrón calculado a partir de ellas, sus cuestionarios de bienestar (PHQ-9) y el resumen de su cuenta que aparece en su lista de casos — desde su portal de terapeuta. No puede cambiar ni eliminar nada — solo leer, y escribir sus propias notas privadas.\n\nPuede dejar de compartir en cualquier momento; eso termina su acceso de inmediato, pero no puede desleer lo que ya haya leído. Se le pedirá su contraseña.",
  "share.revokeTitle": "¿Dejar de compartir con {name}?",
  "share.revokeBody": "Su acceso termina de inmediato. Conserva todo lo que ya haya leído. Se le pedirá su contraseña.",
  "share.stopSharing": "Dejar de compartir",
  "share.noAccount": "no hay ninguna cuenta guardada en este dispositivo",
  "share.grantDoneTitle": "Compartir iniciado",
  "share.grantDoneBody": "{name} ya puede leer sus entradas, patrones y cuestionarios de bienestar desde su portal.",
  "share.revokeDoneTitle": "Compartir detenido",
  "share.revokeDoneBody": "El acceso de esa persona ha terminado.",
  "share.unavailableTitle": "Compartir con terapeutas no disponible",
  "share.unavailableBody": "Este servidor no ha activado el compartir con profesionales verificados. No se enviará ningún código de emparejamiento ni datos del diario.",
  "share.unreachableTitle": "No se puede contactar al servidor",
  "share.unreachableBody": "No se pudo confirmar la disponibilidad del compartir — revise su conexión e inténtelo de nuevo. No se envía ningún código ni dato del diario hasta que se confirme.",
  "share.sharingNowLabel": "Compartiendo ahora",
  "share.notSharingNote": "No está compartiendo con nadie. Sus entradas siguen visibles solo para usted.",
  // L-66: una carga FALLIDA es estado desconocido, no "no está compartiendo".
  "share.listFailedNote":
    "No se pudo cargar con quién está compartiendo en este momento — revise su conexión y vuelva a abrir esta pantalla antes de confiar en esta lista.",
  "share.sharingSince": "Compartiendo desde {date}",
  "share.stoppedOn": "Detenido {date}",
  // Auditoría 2026-09-28 (INFO): consentimientos no activos sin revoked_at
  // (servidores antiguos) — el estado simple en vez de "Detenido " + fecha vacía.
  "share.stopped": "Detenido",
  "share.addLabel": "Agregue a su terapeuta",
  "share.addBody": "Pida a su terapeuta un código de emparejamiento desde su portal y escríbalo aquí. Los códigos expiran después de 15 minutos.",
  // SAS (2026-09-26): fija la expectativa junto al campo del código — tras
  // la búsqueda, un código de coincidencia de 6 dígitos y la huella de la
  // llave deben compararse con el terapeuta por otro canal antes de compartir.
  "share.sasIntro":
    "Después de escribir el código, esta app muestra un código de coincidencia y la huella de una llave. Léale ambos a su terapeuta y compruebe que coinciden con lo que muestra su portal antes de compartir nada.",
  "share.codePlaceholder": "p. ej. 7X2KQM4N",
  "share.codeA11y": "Código de emparejamiento del terapeuta",
  "share.lookingUp": "Buscando…",
  "share.findTherapist": "Encontrar a mi terapeuta",
  "share.fingerprintNote":
    "Huella de la llave: {fingerprint}\nLéala de vuelta a su terapeuta y compruebe que coincide con la que muestra su portal — una discrepancia significa que la llave fue sustituida en el camino.",
  // SAS (2026-09-26): la suma de verificación del emparejamiento calculada
  // por el servidor sobre (código, llave pública, su cuenta). Una llave
  // sustituida la cambia; dos personas comparándola por otro canal son la
  // detección. Solo se muestra cuando tiene un formato válido.
  "share.sasNote":
    "Código de coincidencia: {sas}\nLéalo de vuelta a su terapeuta y compruebe que coincide con el que muestra su portal para este emparejamiento — una discrepancia significa que el emparejamiento podría haber sido alterado. No continúe.",
  // C-7 (2026-09-21): la comprobación de la huella es una ACCIÓN — el
  // consentimiento solo continúa tras pulsar «las huellas coinciden».
  "share.fingerprintsMatch": "Las huellas coinciden — continuar",
  "share.fingerprintsDontMatch": "No coinciden",
  "share.mismatchTitle": "No continúe",
  "share.mismatchBody":
    "Si las huellas no coinciden, el emparejamiento podría haber sido interceptado. Contacte a su terapeuta por un canal de confianza antes de compartir nada.",
  "share.disclosure":
    "Compartir le permite a esa persona leer sus entradas del diario, sus patrones e ideas, sus cuestionarios de bienestar (PHQ-9) y su línea de resumen en la lista de casos (nunca cambiar nada), y escribir sus propias notas privadas. Puede detenerlo en cualquier momento; lo que ya se leyó no se puede desleer.",
  "share.shareWithName": "Compartir con {name}",
  "share.reauthGrantTitle": "Escriba su contraseña para compartir con {name}",
  "share.reauthRevokeTitle": "Escriba su contraseña para dejar de compartir",
  // M-25: el servidor reporta una versión de divulgación que esta app no
  // conoce — estado sereno, sin ofrecer nuevos permisos hasta alinear.
  "share.termsUpdatedTitle": "Términos de compartir actualizados",
  "share.termsUpdatedBody":
    "Lo que un terapeuta puede leer cambió — ahora incluye sus cuestionarios de bienestar (PHQ-9). Actualice esta app y comparta de nuevo para ver y aceptar los términos vigentes. Su compartir existente sigue funcionando, y puede detenerlo abajo cuando quiera.",
  // M-25: el servidor rechazó el permiso porque la divulgación revisada en
  // pantalla ya no es la vigente (409 disclosure_outdated). No se compartió nada.
  "share.grantOutdatedTitle": "Términos de compartir actualizados",
  "share.grantOutdatedBody":
    "Los términos de compartir cambiaron antes de que esto se enviara, así que no se compartió nada. Nada sobre usted cambió en el servidor. Comience de nuevo para revisar los términos vigentes — ahora incluyen sus cuestionarios de bienestar (PHQ-9).",
  // --- voice journaling (VOICE_PLAN 2026-09-29) -----------------------------
  "entry.micRecord": "Grabar en su lugar",
  "entry.micRecording": "Grabando…",
  "entry.micRecordingNote": "Hable en cualquier idioma — revisará la transcripción antes de guardar nada.",
  "entry.micStop": "Detener grabación",
  "entry.voiceDiscardTake": "Solo texto",
  "entry.voiceTranscribing": "Transcribiendo su grabación…",
  "entry.voiceReviewTitle": "Su grabación",
  "entry.voiceLanguage": "Idioma detectado: {lang}",
  "entry.voiceEnglishPreview": "Traducción al inglés (para su terapeuta)",
  "entry.voiceKeepOn": "Conservar la grabación 30 días — toque para desactivar",
  "entry.voiceKeepOff": "La grabación se eliminará al guardar — toque para conservarla 30 días",
  "entry.voiceConsentNeeded": "El diario por voz necesita su permiso — actívelo en Ajustes.",
  "entry.voiceUnavailable": "El diario por voz no está disponible en este servidor.",
  "entry.voiceMicDenied": "Se denegó el acceso al micrófono — permítalo en los ajustes de la app para grabar.",
  "entry.voiceRecordFailed": "La grabación falló — inténtelo de nuevo.",
  "entry.voiceTranscribeFailed": "La transcripción falló — inténtelo de nuevo.",
  "entry.voiceAudioNotKept": "La entrada se guardó, pero no se pudo conservar la grabación.",
  "entry.voiceAudioQueuedNote": "Guardado sin conexión. La grabación necesita conexión y no se conservó — la transcripción está a salvo.",
  // M3: una transcripción reemplaza lo escrito — confirmar antes de perderlo.
  "entry.voiceReplaceTitle": "¿Grabar en lugar de escribir?",
  "entry.voiceReplaceBody":
    "La transcripción reemplazará lo que ha escrito hasta ahora. Sus palabras escritas se perderán.",
  "entry.voiceReplaceConfirm": "Grabar en su lugar",
  "history.playRecording": "Reproducir grabación",
  "history.stopRecording": "Detener reproducción",
  "history.deleteRecording": "Eliminar grabación",
  "history.voiceBadge": "grabada",
  // --- consentimiento y compartir por voz (VOICE_PLAN 2026-09-29, auditoría C5) --
  // Sección de voz en Ajustes: mismo texto y nivel que la vista de Ajustes web.
  "settings.voiceLabel": "Diario por voz",
  "settings.voiceRow": "Permitir el diario por voz",
  "settings.voiceA11y": "Permitir el diario por voz",
  "settings.voiceNote":
    "Grabe entradas en cualquier idioma. Su grabación se envía a {provider} para transcribirla y se elimina inmediatamente después; solo el texto cifrado se guarda. Las grabaciones que conserve se almacenan cifradas durante 30 días. Desactivado por defecto; se necesita su contraseña para cambiarlo.",
  "settings.voiceStaleNote":
    "El proveedor de transcripción del servidor cambió — vuelva a activarlo para revisar y aceptar los nuevos términos.",
  "settings.voiceNotOffered": "Este servidor no ofrece el diario por voz.",
  "settings.reauthVoiceTitle": "Escriba su contraseña para {action} el diario por voz",
  // Pantalla de compartir: alcance adicional sobre una concesión activa.
  "share.voiceTitle": "Permitir que su terapeuta escuche sus grabaciones",
  "share.voiceOnBody":
    "Su terapeuta ya puede leer sus entradas (y su traducción al inglés). Activar esto también le permite reproducir las grabaciones de voz que conserve — el tono puede transmitir lo que el texto no. Conserva este acceso solo mientras el compartir esté activo.",
  "share.voiceOffBody":
    "Su terapeuta ya no podrá reproducir las grabaciones de voz adjuntas a sus entradas. Seguirá pudiendo leer las entradas, y una grabación que ya haya descargado no se puede desoir.",
  "share.voiceOn": "Mi terapeuta puede escuchar mis grabaciones",
  "share.voiceOff": "Mi terapeuta no puede escuchar mis grabaciones",
  "share.voiceA11y": "Permitir que {name} escuche mis grabaciones",
  "share.voiceNote":
    "Su terapeuta ya puede leer sus entradas (y su traducción al inglés). Activar esto también le permite reproducir las grabaciones de voz que conserve — el tono puede transmitir lo que el texto no. Conserva este acceso solo mientras el compartir esté activo.",
  "share.reauthShareVoiceTitle": "Escriba su contraseña para cambiar lo que {name} puede escuchar",
};

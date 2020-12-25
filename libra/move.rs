fn check_program(
    prog: Result<parser::ast::Program, Errors>,
    sender_opt: Option<Address>,
) -> Result<cfgir::ast::Program, Errors> {
    let (eprog, errors) = expansion::translate::program(prog?, sender_opt);
    let (nprog, errors) = naming::translate::program(eprog, errors);
    let (tprog, errors) = typing::translate::program(nprog, errors);
    check_errors(errors)?;
    let (hprog, errors) = hlir::translate::program(tprog);
    let (cprog, errors) = cfgir::translate::program(errors, hprog);
    check_errors(errors)?;
    Ok(cprog)
}

fn compile_program(
    prog: Result<parser::ast::Program, Errors>,
    sender_opt: Option<Address>,
) -> Result<Vec<CompiledUnit>, Errors> {
    let cprog = check_program(prog, sender_opt)?;
    to_bytecode::translate::program(cprog)
}


//parser::ast
pub enum Kind_ {
    // Kind representing all types
    Unknown,
    // Linear resource types
    Resource,
    // Explicitly copyable types
    Affine,
    // Implicitly copyable types
    Copyable,
}
pub enum Type_ {
    // N
    // N<t1, ... , tn>
    Apply(Box<ModuleAccess>, Vec<Type>),
    // &t
    // &mut t
    Ref(bool, Box<Type>),
    // (t1,...,tn):t
    Fun(Vec<Type>, Box<Type>),
    // ()
    Unit,
    // (t1, t2, ... , tn)
    // Used for return values and expression blocks
    Multiple(Vec<Type>),
}

// TParam: type parameter

// naming::Context
// scoped structs,functions,constants | unscoped builtin types
ET::Apply(sp!(_, EN::Name(n)), tys) => match context.resolve_unscoped_type(&n);
ET::Apply(sp!(loc, EN::ModuleAccess(m, n)), tys) => match context.resolve_module_type(loc, &m, &n);
// scope means path?

// naming
fn Context::resolve_module_type() {
    error("unbound module {}");
    error("invalid module access. unbound struct {} in mdoule {}");
}
fn resolve_module_function();
fn resolve_unscoped_type(&mut self, n: &Name) -> Option<ResolvedType> {
    match self.unscoped_types.get(&n.value) {
        None => {
            self.error(vec![(n.loc,format!("Unbound type '{}' in current scope", n),)]);
            None
        }
        Some(rn) => Some(rn.clone()),
    }
}
pub struct TParamID(pub u64);
pub struct TParam {
    pub id: TParamID,
    pub user_specified_name: Name,
    pub kind: Kind,
}
enum ResolvedType {
    TParam(Loc, N::TParam),
    BuiltinType,
}
struct Context {
    errors: Errors,
    current_module: Option<ModuleIdent>,
    scoped_types: BTreeMap<ModuleIdent, BTreeMap<String, (Loc, ModuleIdent, Option<Kind>)>>,
    unscoped_types: BTreeMap<String, ResolvedType>,
    scoped_functions: BTreeMap<ModuleIdent, BTreeMap<String, Loc>>,
    unscoped_constants: BTreeMap<String, Loc>,
    scoped_constants: BTreeMap<ModuleIdent, BTreeMap<String, Loc>>,
}
fn Context::bind_type(&mut self, s: String, rt: ResolvedType) {
    self.unscoped_types.insert(s, rt);
}
fn Context::bind_constant(&mut self, s: String, loc: Loc) {
    self.unscoped_constants.insert(s, loc);
}
fn script(context: &mut Context, escript: E::Script) -> N::Script {
    let E::Script {
        loc,
        constants: econstants,
        function_name,
        function: efunction,
        specs: _specs,
    } = escript;
    let outer_unscoped = context.save_unscoped();
    for (n, _) in &econstants {
        let sp!(loc, s) = n.0;
        context.bind_constant(s, loc)
    }
    let inner_unscoped = context.save_unscoped();
    let constants = econstants.map(|name, c| {
        context.restore_unscoped(inner_unscoped.clone());
        constant(context, name, c)
    });
    context.restore_unscoped(inner_unscoped);
    let function = function(context, function_name.clone(), efunction);
    context.restore_unscoped(outer_unscoped);
    N::Script {
        loc,
        constants,
        function_name,
        function,
    }
}

// ######################################################################
// expansion

type ModuleMembers = BTreeMap<Name, ModuleMemberKind>;
enum ModuleMemberKind {
    Constant,
    Function,
    Struct,
    Schema,
}
pub struct AliasSet {
    pub modules: BTreeSet<Name>,
    pub members: BTreeSet<Name>,
}
pub struct AliasMap {
    modules: RememberingUniqueMap<Name, ModuleIdent>,
    members: RememberingUniqueMap<Name, (ModuleIdent, Name)>,
    current_scope: AliasSet,
}
struct Context {
    module_members: UniqueMap<ModuleIdent, ModuleMembers>,
    errors: Errors,
    address: Option<Address>,
    aliases: AliasMap,
    is_source_module: bool,
    in_spec_context: bool,
    exp_specs: BTreeMap<SpecId, E::SpecBlock>,
}

if !is_valid_struct_constant_or_schema_name(&n.value) {
    let msg = format!(
        "Invalid {} name '{}'. {} names must start with 'A'..'Z'",
        lcase, n, ucase,
    );
    context.error(vec![(n.loc, msg)]);
    return Err(());
}
let msg = format!(
    "Invalid {case} name '{restricted}'. '{restricted}' is restricted and cannot be used to \
     name a {case}",
    case = case,
    restricted = restricted,
);
fn fields<T>(
    context: &mut Context,
    loc: Loc,
    case: &str,
    verb: &str,
    xs: Vec<(Field, T)>,
) -> Fields<T> {
    let mut fmap = UniqueMap::new();
    for (idx, (field, x)) in xs.into_iter().enumerate() {
        if let Err(old_loc) = fmap.add(field.clone(), (idx, x)) {
            context.error(vec![
                (loc, format!("Invalid {}", case)),
                (
                    field.loc(),
                    format!("Duplicate {} given for field '{}'", verb, field),
                ),
                (old_loc, "Previously defined here".into()),
            ])
        }
    }
    fmap
}
fn check_valid_local_name(context: &mut Context, v: &Var) {
    fn is_valid(s: &str) -> bool {
        s.starts_with('_') || s.starts_with(|c| matches!(c, 'a'..='z'))
    }
    if !is_valid(v.value()) {
        let msg = format!(
            "Invalid local name '{}'. Local names must start with 'a'..'z' (or '_')",
            v,
        );
        context.error(vec![(v.loc(), msg)])
    }
}
fn check_restricted_name(
    context: &mut Context,
    case: &str,
    sp!(loc, n_): &Name,
    restricted: &str,
) -> Result<(), ()> {
    if n_ != restricted {
        return Ok(());
    }
    let msg = format!(
        "Invalid {case} name '{restricted}'. '{restricted}' is restricted and cannot be used to \
         name a {case}",
        case = case,
        restricted = restricted,
    );
    context.error(vec![(*loc, msg)]);
    Err(())
}
fn module(
    context: &mut Context,
    address: Option<Address>,
    module_map: &mut UniqueMap<ModuleIdent, E::ModuleDefinition>,
    module_def: P::ModuleDefinition,
) {
    assert!(context.address == None);
    set_sender_address(context, module_def.loc, address);
    let (mident, mod_) = module_(context, module_def);
    if let Err((old_loc, _)) = module_map.add(mident.clone(), mod_) {
        let mmsg = format!("Duplicate definition for module '{}'", mident);
        context.error(vec![
            (mident.loc(), mmsg),
            (old_loc, "Previously defined here".into()),
        ]);
    }
    context.address = None
}

// ########################################################################

// typing

pub struct Context {
    pub modules: UniqueMap<ModuleIdent, ModuleInfo>,

    pub current_module: Option<ModuleIdent>,
    pub current_function: Option<FunctionName>,
    pub current_script_constants: Option<UniqueMap<ConstantName, ConstantInfo>>,
    pub return_type: Option<Type>,
    locals: UniqueMap<Var, Type>,

    pub subst: Subst,
    pub constraints: Constraints,

    pub in_loop: bool,
    pub break_type: Option<Type>,

    errors: Errors,
}

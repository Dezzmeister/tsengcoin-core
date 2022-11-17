use std::collections::HashMap;
use std::error::Error;

pub const WITH_MINER_FLAG: &str = "--with-miner";
pub const WALLET_PATH_VAR: &str = "wallet-path";

pub struct Command<T> {
    pub processor: CommandProcessor<T>,
    pub expected_fields: Vec<Field>
}

pub type CommandProcessor<T> = fn (command_name: &String, invocation: &CommandInvocation, state: Option<T>) -> Result<(), Box<dyn Error>>;
pub type CommandMap<T> = HashMap<String, Command<T>>;
pub struct CommandInvocation {
    pub name: String,
    pub flags: Vec<String>,
    pub args: Vec<String>,
    pub vars: HashMap<String, String>,
    pub fields: HashMap<String, String>
}

impl CommandInvocation {
    pub fn is_flag_set(&self, flag: &str) -> bool {
        self.flags.contains(&flag.to_owned())
    }

    pub fn get_field(&self, field_name: &str) -> Option<String> {
        self.fields.get(&field_name.to_owned()).cloned()
    }
}

pub struct Field {
    pub name: String,
    pub field_type: FieldType,
}

pub enum FieldType {
    /// A "var" must be passed in as a named variable with --name=value syntax
    Var,

    /// A pos argument is expected to be found at the given position in the args vector
    /// if not passed in as a var
    Pos(usize),

    /// A spaces argument, if not passed in as a var, is expected to be found starting at the given
    /// position. The argument consists of all tokens after and including the one at the given position,
    /// joined by spaces. A spaces argument should only ever be the last argument expected.
    Spaces(usize)
}

impl Field {
    pub fn new(name: &str, field_type: FieldType) -> Self {
        Field { name: name.to_owned(), field_type }
    }
}

pub fn dispatch_command<T>(args: &Vec<String>, map: &CommandMap<T>, state: Option<T>) {
    if args.len() < 1 {
        println!("Missing command");
        return;
    }

    let cmd_name = &args[0];

    let command = match map.get(cmd_name) {
        Some(obj) => obj.to_owned(),
        None => {
            println!("Unrecognized command: {cmd_name}");
            return;
        }
    };

    let invocation = decompose_raw_args(args, &command.expected_fields).expect("Failed to decompose command");

    match (command.processor)(cmd_name, &invocation, state) {
        Err(err) => println!("Error executing command: {:?}", err),
        Ok(_) => (),
    }
}

fn decompose_raw_args(raw_args: &Vec<String>, expected_fields: &Vec<Field>) -> Result<CommandInvocation, Box<dyn Error>> {
    let cmd_name = &raw_args[0];
    let trimmed_args = &raw_args[1..];
    let mut assignments: HashMap<String, String> = HashMap::new();
    let (specials, ordered_args): (Vec<String>, Vec<String>) = 
        trimmed_args
            .iter()
            .map(|s| s.to_owned())
            .partition(|s| s.starts_with("--"));

    let (assignment_strs, flags): (Vec<String>, Vec<String>) = 
        specials
            .iter()
            .map(|s| s.to_owned())
            .partition(|s| s.contains('='));

    for assignment in assignment_strs {
        let pair: Vec<&str> = assignment.split("=").collect();
        let key = pair[0].trim_start_matches("--").to_owned();
        let value = pair[1].to_owned();

        assignments.insert(key, value);
    }

    let mut fields: HashMap<String, String> = HashMap::new();

    println!("{:?}", ordered_args);

    for Field {name, field_type} in expected_fields {
        let var_field = assignments.get(name).cloned();

        match (field_type, var_field) {
            (_, Some(field)) => drop(fields.insert(name.to_owned(), field)),
            (FieldType::Pos(num), None) if num.to_owned() < ordered_args.len() => drop(fields.insert(name.to_owned(), ordered_args[num.to_owned()].clone())),
            (FieldType::Spaces(pos), None) if pos.to_owned() < ordered_args.len() => drop(fields.insert(name.to_owned(), ordered_args[pos.to_owned()..].join(" "))),
            (FieldType::Pos(_) | FieldType::Spaces(_), None) => return Err(format!("Not enough arguments: missing expected argument {name}"))?,
            (FieldType::Var, None) => return Err(format!("Missing expected argument {name}. Pass this in with --{name}=<value>"))?
        };
    }

    let out = CommandInvocation {
        name: cmd_name.to_owned(),
        flags,
        args: ordered_args,
        vars: assignments,
        fields
    };

    Ok(out)
}

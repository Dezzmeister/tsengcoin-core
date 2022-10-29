use std::collections::HashMap;
use std::error::Error;

pub type CommandProcessor<T> = fn (command_name: &String, args: &Vec<String>, state: Option<T>) -> Result<(), Box<dyn Error>>;
pub type CommandMap<T> = HashMap<String, CommandProcessor<T>>;

pub fn dispatch_command<T>(args: &Vec<String>, map: &CommandMap<T>, state: Option<T>) {
    if args.len() < 1 {
        println!("Missing command");
        return;
    }

    let cmd_name = &args[0];
    let processor = match map.get(cmd_name) {
        Some(obj) => obj.to_owned(),
        None => {
            println!("Unrecognized command: {cmd_name}");
            return;
        }
    };

    match processor(cmd_name, &args[1..].to_vec(), state) {
        Err(err) => println!("Error executing command: {:?}", err),
        Ok(_) => (),
    }
}

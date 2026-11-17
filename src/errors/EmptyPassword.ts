export class EmptyPassword extends Error {
    constructor(){
        super();
        this.message = 'The password cannot be blank'
    }
}
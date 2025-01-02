import { Body, Controller, Post } from '@nestjs/common';

@Controller('users')
export class UsersController {
    @Post('create-user')
    async createUser(@Body() {email} : {email : string}) {
        // return await this.emailCheckerService.createUser(email);
    }

    @Post('get-single-mails')
    async getSingleMails(@Body() {email} : {email : string}) {

    }

    @Post('get-lists-mails')
    async getListsMails(@Body() {email} : {email : string}) {
        
    }
}

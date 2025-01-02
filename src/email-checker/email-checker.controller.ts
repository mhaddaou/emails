import { Body, Controller, Post } from '@nestjs/common';
import { EmailCheckerService } from './email-checker.service';
import VerifyOneDto from './dtos/verify-one.dto';
import VerifyManyDto from './dtos/verify-many.dto';

@Controller('email-checker')
export class EmailCheckerController {
    constructor(private readonly emailCheckerService : EmailCheckerService){}

    @Post('verify-one')
    async verifyOneEmail(@Body() data : VerifyOneDto) {
        return await this.emailCheckerService.verifyOneEmail(data);
    }

    @Post('verify-many')
    async verifyManyEmails(@Body() data : VerifyManyDto) {
        return await this.emailCheckerService.verifyManyEmail(data);
    }

    @Post('create-user')
    async createUser(@Body() {email} : {email : string}) {
        return await this.emailCheckerService.createUser(email);
    }
}

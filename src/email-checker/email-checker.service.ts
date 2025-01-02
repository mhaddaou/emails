import { Injectable, Logger } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import * as mailchecker from 'mailchecker';
import * as fs from 'fs';
import * as blacklist from '../lib/blacklist.json';
import * as nodemailer from 'nodemailer';
import * as net from 'net';
import * as tls from 'tls';

import {
  BrowserContext,
  chromium,
  firefox,
  type Browser,
  type Page,
} from 'playwright';
import { InjectModel } from '@nestjs/mongoose';
import { Emails } from './schemas/emails.schema';
import { Users } from './schemas/users.schema';
import { Model } from 'mongoose';
import VerifyOneDto from './dtos/verify-one.dto';
import { promisify } from 'util';
import * as dns from 'dns';
import VerifyManyDto from './dtos/verify-many.dto';
const resolveMx = promisify(dns.resolveMx);
const resolveTxt = promisify(dns.resolveTxt);

export interface DnsVerificationResult {
  hasMxRecord: boolean;
  hasSPF: boolean;
  hasDMARC: boolean;
  mxRecords: dns.MxRecord[];
  spfRecord?: string;
  dmarcRecord?: string;
  errors?: string[];
}
export interface SmtpVerificationResult {
  success: boolean;
  exists: boolean;
  message: string;
}

@Injectable()
export class EmailCheckerService {
  constructor(
    @InjectModel(Emails.name) private readonly emailsModel: Model<Emails>,
    @InjectModel(Users.name) private readonly usersModel: Model<Users>,
  ) {}

  private readonly roleKeywords = [
    // English roles
    'admin',
    'administrator',
    'support',
    'info',
    'help',
    'service',
    'contact',
    'team',
    'sales',
    'marketing',
    'hr',
    'billing',
    'security',
    'noreply',
    'no-reply',
    'webmaster',
    'postmaster',
    'hostmaster',
    'office',
    'careers',
    'jobs',
    'recruitment',
    'it',
    'tech',
    'feedback',
    'enquiries',
    'inquiries',
    'helpdesk',
    'support',
    'services',
    'orders',
    'shipping',
    'accounts',
    'accounting',
    'finance',
    'payroll',
    'purchasing',
    'legal',
    'media',
    'press',
    'news',
    'newsletter',
    'subscriptions',
    'unsubscribe',
    'abuse',
    'spam',
    'compliance',
    'privacy',
    'careers',
    'development',
    'dev',
    'operations',
    'ops',
    'research',
    'partners',
    'partnership',
    'reception',
    'supply',
    'logistics',
    'warehouse',
    'customercare',
    'customersupport',
    'customerservice',
    'complaints',
    'returns',
    'quality',
    'training',
    'facilities',
    'maintenance',
    'events',
    'social',
    'digital',
    'online',
    'website',
    'web',
    'analytics',
    'data',
    'systems',
    'network',
    'infrastructure',
    'project',
    'projects',
    'procurement',
    'vendor',
    'suppliers',
    'corporate',
    'enterprise',
    'business',
    'community',
    'public',
    'external',
    'internal',
    'global',
    'local',
    'regional',
    'group',
    'department',
    'staff',
    'employee',
    'personnel',
    'talent',
    'benefits',
    'compensation',
    'relations',
    'success',
    'experience',
    'engagement',
    'brand',
    'creative',

    // French roles
    'assistance',
    'aide',
    'bureau',
    'comptabilite',
    'direction',
    'secretariat',
    'accueil',
    'commercial',
    'ventes',
    'equipe',
    'service-client',
    'contact',
    'information',
    'administration',
    'gestion',
    'rh',
    'facturation',
    'securite',
    'ne-pas-repondre',
    'communication',
    'recrutement',
    'emplois',
    'carrieres',
    'technique',
    'informatique',
    'commandes',
    'expeditions',
    'livraison',
    'finances',
    'paie',
    'achats',
    'juridique',
    'presse',
    'actualites',
    'newsletter',
    'desabonnement',
    'abonnements',
    'conformite',
    'confidentialite',
    'developpement',
    'partenariats',
    'recherche',
    'formation',
    'stage',
    'stages',
    'logistique',
    'entrepot',
    'qualite',
    'evenements',
    'maintenance',
    'systemes',
    'projets',
    'approvisionnement',
    'fournisseurs',
    'entreprise',
    'communaute',
    'personnel',
    'avantages',
    'experience-client',
    'engagement',
    'marque',
    'creation',
    'social',
    'commanditaire',
    'departement',
    'groupe',
    'succursale',
    'siege',
    'exploitation',
    'production',
    'atelier',
    'ressources',
    'talents',
    'apprentissage',
    'conseil',
    'consultation',
    'innovation',

    // Additional international variations
    'info-fr',
    'info-en',
    'info-uk',
    'info-us',
    'support-fr',
    'support-en',
    'help-fr',
    'help-en',

    // Industry specific
    'reservations',
    'bookings',
    'tickets',
    'sales',
    'academic',
    'faculty',
    'admissions',
    'alumni',
    'donations',
    'fundraising',
    'grants',
    'sponsors',
    'editorial',
    'submissions',
    'studios',
    'production',
  ];

  private readonly freeEmailProviders = [
    'gmail.com',
    'yahoo.com',
    'outlook.com',
    'hotmail.com',
    'icloud.com',
    'mail.com',
    'aol.com',
    'zoho.com',
  ];

  private readonly userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  ];

  private readonly concurrencyLimit = 2;

  private async randomDelay(min = 500, max = 2000) {
    const delay = Math.floor(Math.random() * (max - min + 1) + min);
    await new Promise((resolve) => setTimeout(resolve, delay));
  }

  private async typeText(
    page: Page,
    selector: string,
    text: string,
  ): Promise<void> {
    for (const char of text) {
      await page.type(selector, char, { delay: Math.random() * 150 + 30 });
      await this.randomDelay(30, 100);
    }
  }

  private async simulateHumanClick(
    page: Page,
    selector: string,
  ): Promise<void> {
    const button = await page.$(selector);
    if (button) {
      const box = await button.boundingBox();
      if (box) {
        await page.mouse.move(
          box.x + box.width * (0.3 + Math.random() * 0.4),
          box.y + box.height * (0.3 + Math.random() * 0.4),
          { steps: 5 },
        );
        await this.randomDelay(100, 300);
        await page.mouse.down();
        await this.randomDelay(50, 150);
        await page.mouse.up();
      }
    }
  }

  private async initBrowser(): Promise<{
    browser: Browser;
    context: BrowserContext;
    page: Page;
  }> {
    const browser = await chromium.launch({
      headless: false,
      args: [
        '--disable-blink-features=AutomationControlled',
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-infobars',
        '--window-position=0,0',
        '--ignore-certifcate-errors',
        '--ignore-certifcate-errors-spki-list',
      ],
    });

    const context = await browser.newContext({
      viewport: { width: 1920, height: 1080 },
      userAgent:
        this.userAgents[Math.floor(Math.random() * this.userAgents.length)],
      permissions: ['geolocation'],
      geolocation: { latitude: 51.5074, longitude: -0.1278 },
      locale: 'en-US',
    });

    const page = await context.newPage();
    await page.addInitScript(() => {
      Object.defineProperty(navigator, 'webdriver', {
        get: () => undefined,
      });
      (window.navigator as any).chrome = {
        runtime: {},
      };
    });

    return { browser, context, page };
  }

  async checkGoogleAccount(
    email: string,
  ): Promise<{ exists: boolean; message: string }> {
    let browser: Browser = null;
    let context: BrowserContext = null;
    let page: Page = null;

    try {
      ({ browser, context, page } = await this.initBrowser());

      await page.goto('https://accounts.google.com');
      await page.waitForSelector('input[type="email"]');
      await this.randomDelay();

      await this.typeText(page, 'input[type="email"]', email);
      await this.randomDelay();

      await this.simulateHumanClick(page, 'button:has-text("Next")');
      await this.randomDelay();
      await page.waitForLoadState('networkidle');
      await this.randomDelay();
      const accountNotFound = await page
        .getByText('Couldn’t find your Google')
        .isVisible();

      return {
        exists: !accountNotFound,
        message: accountNotFound ? 'Account not found' : 'Account exists',
      };
    } catch (error) {
      Logger.error(
        `Google account check failed: ${error.message}`,
        error.stack,
      );
      return { exists: false, message: error.message };
    } finally {
      if (page) await page.close();
      if (context) await context.close();
      if (browser) await browser.close();
    }
  }

  async checkYahooAccount(
    email: string,
  ): Promise<{ exists: boolean; message: string }> {
    let browser: Browser = null;
    let context: BrowserContext = null;
    let page: Page = null;

    try {
      ({ browser, context, page } = await this.initBrowser());

      await page.goto('https://login.yahoo.com/');
      await page.waitForSelector('input[name="username"]');
      await this.randomDelay();

      await this.typeText(page, 'input[name="username"]', email);
      await this.randomDelay();

      // Click the Enter
      await page.locator('input[name="username"]').press('Enter');

      await this.randomDelay(2000, 3000);

      try {
        // Wait specifically for the error message
        const accountNotFound = await page
          .getByText("Sorry, we don't recognize")
          .isVisible();

        if (accountNotFound) {
          return { exists: false, message: 'Account not found' };
        } else {
          await page.waitForLoadState('load');
          await this.randomDelay();

          // Check if account is desactivated
          const accountDesactivated = await page
            .getByText('This account has been')
            .isVisible();

          if (accountDesactivated) {
            return { exists: false, message: 'Account desactivated' };
          } else {
            return { exists: true, message: 'Account exists' };
          }
        }
      } catch (error) {
        return { exists: false, message: 'Error checking account' };
      }
    } catch (error) {
      Logger.error(
        `Microsoft account check failed: ${error.message}`,
        error.stack,
      );
      return { exists: false, message: error.message };
    } finally {
      if (page) await page.close();
      if (context) await context.close();
      if (browser) await browser.close();
    }
  }

  async checkMicrosoftAccount(
    email: string,
  ): Promise<{ exists: boolean; message: string }> {
    let browser: Browser = null;
    let context: BrowserContext = null;
    let page: Page = null;

    try {
      ({ browser, context, page } = await this.initBrowser());

      await page.goto('https://login.microsoftonline.com/');
      await page.waitForSelector('input[type="email"]');
      await this.randomDelay();

      await this.typeText(page, 'input[type="email"]', email);
      await this.randomDelay();

      // Click the Next button
      await page.keyboard.press('Enter');

      await this.randomDelay(2000, 3000);

      try {
        // Wait specifically for the error message
        const accountNotFound = await page
          .getByText("That Microsoft account doesn'")
          .isVisible();

        if (accountNotFound) {
          return { exists: false, message: 'Account not found' };
        }

        const sc = await page.getByText('This username may be').isVisible();
        if (sc) {
          return { exists: false, message: 'Account not found' };
        }
        const sc1 = await page
          .getByText("We couldn't find an account")
          .isVisible();
        if (sc1) {
          return { exists: false, message: 'Account not found' };
        }
        return { exists: true, message: 'Account exists' };
      } catch (error) {
        return { exists: false, message: 'Error checking account' };
      }
    } catch (error) {
      Logger.error(
        `Microsoft account check failed: ${error.message}`,
        error.stack,
      );
      return { exists: false, message: error.message };
    } finally {
      if (page) await page.close();
      if (context) await context.close();
      if (browser) await browser.close();
    }
  }

  async createUser(email: string) {
    try {
      const isExist = await this.usersModel.findOne({ email });
      if (!isExist) {
        const user = await this.usersModel.create({ email });
        await user.save();
        return user;
      }
    } catch (err) {
      Logger.error(err.message);
    }
  }
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async verifyManyEmail(data: VerifyManyDto) {


    let dataa = [] ;
    for (let email of data.emails){
      const res = await this.verifyOneEmail({email : data.email, check: email});
      console.log(res);
      dataa.push(res);
      // console.log(email);
      await this.sleep(2000);
    }  
    return dataa;


    const listId = uuidv4();
    const mailsAlready = await this.emailsModel.find().select('email');
    // remove duplicated emails
    const filteredData = Array.from(new Set<string>(data.emails));
    // Extract only the email addresses from the result
    const emailsInDb = mailsAlready.map((mail) => mail.email);
    const emailsToProcess = filteredData.filter(
      (email) => !emailsInDb.includes(email),
    );

    const emailQueue = [...emailsToProcess];
    const emailsInBoth = filteredData.filter((email) =>
      emailsInDb.includes(email),
    );
    for (let email of emailsInBoth) {
      await this.emailsModel.updateOne({ email }, { $push: { listId } });
    }
    await this.usersModel.updateOne(
      { email: data.email },
      { $push: { listsIds: { id: listId, name: data.name } } },
    );
    console.log(emailsInBoth);
    const processEmails = async () => {
      // Process a batch of emails
      const batch = emailQueue.splice(0, this.concurrencyLimit); // Take the first 'concurrencyLimit' emails

      // Execute all async tasks in the batch concurrently
      await Promise.all(
        batch.map(async (email) => {
          const provider = await this.verifyEmailDns(email);
          // if has dns record process it
          // if (provider) {
          //   // google provider check
          //   if (provider === 'Google') {
          //     const res = await this.checkGoogleAccount(email);
          //     await this.saveEmailsWithRes(res.exists, email, listId);
          //     console.log(res);
          //   }
          //   // microsoft provider check
          //   else if (provider === 'Microsoft') {
          //     const res = await this.checkMicrosoftAccount(email);
          //     await this.saveEmailsWithRes(res.exists, email, listId);

          //     console.log(res);
          //   }
          //   // yahoo provider check
          //   else if (provider === 'Yahoo') {
          //     const res = await this.checkYahooAccount(email);
          //     await this.saveEmailsWithRes(res.exists, email, listId);
          //     console.log(res);
          //   } else {
          //     await this.saveEmailsWithRes(false, email, listId);
          //   }
          // }
          // unknown provider
          // else {
          //   await this.saveEmailsWithRes(false, email, listId);
          // }
        }),
      );
    };

    while (emailQueue.length > 0) {
      await processEmails();
    }
  }

  async saveEmailsWithRes(exists: boolean, email: string, uid: string) {
    try {
      await this.emailsModel.create({ email, check: exists, listId: [uid] });
    } catch (err) {
      Logger.error(err.message);
    }
  }

  async saveSingleEmailWithRes(
    exists: boolean,
    email: string,
    uid: string,
    userEmail: string,
  ) {
    try {
      const createdEmail = await this.emailsModel.create({
        email,
        check: exists,
      });
      await this.usersModel.updateOne(
        { email: userEmail },
        { $push: { singlesIds: createdEmail._id } },
      );
      return { email: email, check: exists };
    } catch (err) {
      Logger.error(err.message);
    }
  }

  checkFreeOrPaid(email: string) {
    const domain = email.split('@')[1].toLowerCase();

    // Check if the domain is in the list of known free providers
    if (this.freeEmailProviders.includes(domain)) {
      return 'Free';
    }

    // If not in the list of free providers, assume it's a paid or custom domain
    return 'Paid';
  }

  isRoleEmail(email: string) {
    const localPart = email.split('@')[0].toLowerCase();

    // Enhanced pattern matching
    return this.roleKeywords.some(
      (keyword) =>
        localPart === keyword ||
        localPart.startsWith(keyword + '.') ||
        localPart.endsWith('.' + keyword) ||
        localPart.includes('.' + keyword + '.') ||
        localPart.includes('-' + keyword) ||
        localPart.includes(keyword + '-') ||
        localPart.includes('_' + keyword) ||
        localPart.includes(keyword + '_'),
    );
  }

  extractMxRecords(mxRecordss) {
    // Extract just the 'exchange' values into an array
    const mxRecords = mxRecordss.map((record) => record.exchange);
    // console.log('from extracted records', mxRecord);

    // Determine the provider based on the exchange domains
    const provider = mxRecords.some((exchange) =>
      exchange.includes('google.com'),
    )
      ? 'Google'
      : mxRecords.some(
            (exchange) =>
              exchange.includes('outlook.com') ||
              exchange.includes('protection.outlook.com'),
          )
        ? 'Microsoft'
        : mxRecords.some((exchange) => exchange.includes('yahoodns.net'))
          ? 'Yahoo'
          : mxRecords.some((exchange) => exchange.includes('cloudflare.net'))
            ? 'CloudflareEmailRouting'
            : 'Unknown';
    return { mxRecords, provider };
  }

  async getInfoEmail(email: string, records: dns.MxRecord[]) {
    const free = this.checkFreeOrPaid(email);
    const role = this.isRoleEmail(email) ? 'Yes' : 'No';
    const dns = await this.verifyEmailDns(email);
    const { mxRecords, provider } = this.extractMxRecords(records);
    const disposable = this.isBlacklisted(email);
    return { free, role, mxRecords, provider, disposable };
  }
  isBlacklisted(email: string): boolean {
    // Extract the domain from the email address
    const domain = email.split('@')[1];

    // Check if the domain exists in the blacklist
    return blacklist.includes(domain);
  }

  async verifyEmailWithDnsResult(
    email: string,
    dnsResult: DnsVerificationResult,
  ): Promise<boolean> {
    const [user, domain] = email.split('@');
    if (!user || !domain) {
      console.error('Invalid email format');
      return false;
    }

    if (
      !dnsResult.hasMxRecord ||
      !dnsResult.mxRecords ||
      dnsResult.mxRecords.length === 0
    ) {
      console.error('No valid MX records found in DNS result');
      return false;
    }

    // Sort MX records by priority
    const sortedMxRecords = dnsResult.mxRecords.sort(
      (a, b) => a.priority - b.priority,
    );

    for (const mxRecord of sortedMxRecords) {
      try {
        const smtpServer = mxRecord.exchange;
        const emailExists = await this.smtpHandshake(smtpServer, user, domain);

        if (emailExists) {
          return true; // Email is valid
        }
      } catch (error) {
        console.warn(
          `Failed to verify with SMTP server ${mxRecord.exchange}:`,
          error.message,
        );
        continue; // Try the next MX record
      }
    }

    console.error('All MX record checks failed');
    return false;
  }

  async smtpHandshake(
    smtpServer: string,
    user: string,
    domain: string,
  ): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection(25, smtpServer);

      socket.setEncoding('ascii');

      let handshakeState = 0;

      socket.on('data', (data) => {
        console.log('Data recieved:', data);
        switch (handshakeState) {
          case 0: // Initial connection
            if (data.includes('220')) {
              console.log('111111111111111111111');
              console.log(data);

              socket.write(`EHLO ${domain}\r\n`);
              handshakeState++;
            }
            break;
          case 1: // EHLO response
            if (data.includes('250')) {
              console.log('222222222222222222222222');
              console.log(data);
              socket.write(`MAIL FROM:<mhaddaou@${domain}>\r\n`);
              handshakeState++;
            }
            break;
          case 2: // MAIL FROM response
            if (data.includes('250')) {
              console.log('333333333333333333333333');
              socket.write(`RCPT TO:<${user}@${domain}>\r\n`);
              console.log(data);
              handshakeState++;
            }
            break;
          case 3: // RCPT TO response
            if (data.includes('250')) {
              console.log('444444444444444444444444');
              console.log(data);
              socket.end();
              resolve(true); // Email exists
            } else if (data.includes('550')) {
              socket.end();
              resolve(false); // Email does not exist
            }
            break;
        }
      });

      socket.on('error', (error) => {
        console.log(error);
        console.error('Socket error:', error.message);
        socket.destroy();
        reject(error);
      });

      socket.on('timeout', () => {
        console.error('Socket timeout');
        socket.destroy();
        reject(new Error('Timeout'));
      });
    });
  }

  async verifyOneEmail(data: VerifyOneDto) {
    try {
      let score = 0;
      let state = 'Undeliverable';
      const dns = await this.verifyEmailDns(data.check);
      const { free, role, disposable, mxRecords, provider } =
        await this.getInfoEmail(data.check, dns.mxRecords);

      console.log(free, role, disposable, mxRecords, provider);
      if (disposable) {
        const res = await this.emailsModel.create({
          email: data.check,
          score: 5,
          state: 'Risky',
          free,
          role,
          disposable,
          mxRecords,
          SmtpProvider: provider,
          time: new Date(),
        });
        const { listId, ...result } = res.toObject();
        return result;
        
      } else {
        const {exists, message, success} = await this.verifyEmail(data.check, dns);
        console.log('message ', message);
        console.log('success ', success);
        if (exists) {
          score = 99;
          state = 'Deliverable';
        }
        const res = await this.emailsModel.create({
          email: data.check,
          score,
          state,
          free,
          role,
          disposable,
          mxRecords,
          SmtpProvider: provider,
          time: new Date(),
        });
        const { listId, ...result } = res.toObject();
        return result;
      }

      return;

      if (disposable || provider === 'Unknown') {
        const res = await this.emailsModel.create({
          email: data.check,
          score: 5,
          state: 'Risky',
          free,
          role,
          disposable,
          mxRecords,
          SmtpProvider: provider,
          time: new Date(),
        });
        const { listId, ...result } = res.toObject();
        return result;
      } else {
        let score = 0;
        let state = 'Undeliverable';
        if (provider === 'Google') {
          const { exists } = await this.checkGoogleAccount(data.check);
          if (exists) {
            score = 99;
            state = 'Deliverable';
          }
          console.log(state);
        } else if (provider === 'Microsoft') {
          const { exists } = await this.checkMicrosoftAccount(data.check);
          if (exists) {
            score = 99;
            state = 'Deliverable';
          }
          console.log(exists);
        } else if (provider === 'Yahoo') {
          const { exists } = await this.checkYahooAccount(data.check);
          if (exists) {
            score = 99;
            state = 'Deliverable';
          }
          console.log(exists);
        } else if (provider === 'CloudflareEmailRouting') {
          score = 99;
          state = 'Deliverable';
        }
        await this.emailsModel.create({
          email: data.check,
          score,
          state,
          free,
          role,
          disposable,
          mxRecords,
          SmtpProvider: provider,
          time: new Date(),
        });
      }
      return;
      const isExist = await this.emailsModel.findOne({ email: data.check });
      const uid = uuidv4();
      // if email is exist in db
      if (isExist) {
        // update user with new singlelist id

        const user = await this.usersModel
          .findOne({
            email: data.email, // Find user by their email
            singlesIds: isExist._id, // Check if emailId exists in singlesIds array
          })
          .exec();

        if (user) {
          // return { email: isExist.email, check: isExist.check };
          return isExist;
        } else {
          console.log('not found id');
        }
      }
      // if email is not exist in db
      // else {
      //   const provider = await this.verifyEmailDns(data.check);
      //   console.log(provider);
      //   return;
      //   if (provider !== 'none') {
      //     // google provider check
      //     if (provider === 'Google') {
      //       const res = await this.checkGoogleAccount(data.check);
      //       return await this.saveSingleEmailWithRes(
      //         res.exists,
      //         data.check,
      //         uid,
      //         data.email,
      //       );
      //       console.log(res);
      //     }
      //     // microsoft provider check
      //     else if (provider === 'Microsoft') {
      //       const res = await this.checkMicrosoftAccount(data.check);
      //       return await this.saveSingleEmailWithRes(
      //         res.exists,
      //         data.check,
      //         uid,
      //         data.email,
      //       );

      //       console.log(res);
      //     }
      //     // yahoo provider check
      //     else if (provider === 'Yahoo') {
      //       const res = await this.checkYahooAccount(data.check);
      //       return await this.saveSingleEmailWithRes(
      //         res.exists,
      //         data.check,
      //         uid,
      //         data.email,
      //       );
      //       console.log(res);
      //     } else {
      //       return await this.saveSingleEmailWithRes(
      //         false,
      //         data.check,
      //         uid,
      //         data.email,
      //       );
      //     }
      //   }
      //   // unknown provider
      //   else {
      //     return await this.saveSingleEmailWithRes(
      //       false,
      //       data.check,
      //       uid,
      //       data.email,
      //     );
      //   }
      // }
    } catch (err) {
      Logger.error(err.message);
    }
  }

  async verifyEmailDns(email: string): Promise<DnsVerificationResult> {
    const domain = email.split('@')[1];
    const result: DnsVerificationResult = {
      hasMxRecord: false,
      hasSPF: false,
      hasDMARC: false,
      mxRecords: [],
      errors: [],
    };

    try {
      // Check MX records
      try {
        const mxRecords = await resolveMx(domain);
        result.hasMxRecord = mxRecords.length > 0;
        result.mxRecords = mxRecords;
      } catch (error) {
        result.errors?.push(`MX lookup failed: ${error.message}`);
      }

      // Check SPF record
      try {
        const txtRecords = await resolveTxt(domain);
        const spfRecord = txtRecords
          .flat()
          .find((record) => record.startsWith('v=spf1'));
        result.hasSPF = !!spfRecord;
        if (spfRecord) {
          result.spfRecord = spfRecord;
        }
      } catch (error) {
        result.errors?.push(`SPF lookup failed: ${error.message}`);
      }

      // Check DMARC record
      try {
        const dmarcRecords = await resolveTxt(`_dmarc.${domain}`);
        const dmarcRecord = dmarcRecords
          .flat()
          .find((record) => record.startsWith('v=DMARC1'));
        result.hasDMARC = !!dmarcRecord;
        if (dmarcRecord) {
          result.dmarcRecord = dmarcRecord;
        }
      } catch (error) {
        result.errors?.push(`DMARC lookup failed: ${error.message}`);
      }
      return result;
    } catch (error) {
      throw new Error(`DNS verification failed: ${error.message}`);
    }
  }

  // async verifyEmail(
  //   email: string,
  //   dnsResult: DnsVerificationResult,
  //   timeout = 10000,
  // ): Promise<SmtpVerificationResult> {
  //   if (!dnsResult.hasMxRecord || dnsResult.mxRecords.length === 0) {
  //     return {
  //       success: false,
  //       exists: false,
  //       message: 'No MX records found for domain',
  //     };
  //   }

  //   const [username, domain] = email.split('@');
  //   const mxRecord = dnsResult.mxRecords[0];

  //   return new Promise((resolve) => {
  //     const socket = new net.Socket();
  //     let buffer = '';
  //     let step = 0;

  //     const timeoutId = setTimeout(() => {
  //       socket.destroy();
  //       resolve({
  //         success: false,
  //         exists: false,
  //         message: 'Connection timeout',
  //       });
  //     }, timeout);

  //     socket.connect(25, mxRecord.exchange, () => {
  //       console.log('Connected to SMTP server');
  //       // Connected successfully
  //     });

  //     socket.on('data', (data) => {
  //       console.log('Raw server response:', data.toString());

  //       buffer += data.toString();

  //       if (buffer.includes('\r\n')) {
  //         const response = buffer.trim();
  //         buffer = '';

  //         switch (step) {
  //           case 0:
  //             console.log('Step 0 - Initial Connection Response:', response);

  //             if (response.startsWith('2')) {
  //               socket.write(`HELO ${domain}\r\n`);
  //               step++;
  //             } else {
  //               this.closeConnection(
  //                 socket,
  //                 timeoutId,
  //                 false,
  //                 'Server not ready',
  //                 resolve,
  //               );
  //             }
  //             break;

  //           case 1:
  //             console.log('Step 1 - HELO Response:', response);

  //             if (response.startsWith('2')) {
  //               socket.write(`MAIL FROM:<mhaddaou@${domain}>\r\n`);
  //               step++;
  //             } else {
  //               this.closeConnection(
  //                 socket,
  //                 timeoutId,
  //                 false,
  //                 'HELO failed',
  //                 resolve,
  //               );
  //             }
  //             break;

  //           case 2:
  //             console.log('Step 2 - MAIL FROM Response:', response);

  //             if (response.startsWith('2')) {
  //               socket.write(`RCPT TO:<${email}>\r\n`);
  //               step++;
  //             } else {
  //               this.closeConnection(
  //                 socket,
  //                 timeoutId,
  //                 false,
  //                 'MAIL FROM failed',
  //                 resolve,
  //               );
  //             }
  //             break;

  //           case 3:
  //             console.log('Step 3 - RCPT TO Response:', response);
  //             if (response.startsWith('250')) {
  //               // Email exists
  //               this.closeConnection(
  //                 socket,
  //                 timeoutId,
  //                 true,
  //                 'Email exists',
  //                 resolve,
  //               );
  //             } else if (
  //               response.includes('blocked using Spamhaus') ||
  //               response.includes('Service unavailable')
  //             ) {
  //               this.closeConnection(
  //                 socket,
  //                 timeoutId,
  //                 false,
  //                 'Verification failed: Server blocked our request (IP listed in Spamhaus)',
  //                 resolve,
  //               );
  //             } else if (response.startsWith('550')) {
  //               // Email doesn't exist
  //               this.closeConnection(
  //                 socket,
  //                 timeoutId,
  //                 false,
  //                 'Email does not exist',
  //                 resolve,
  //               );
  //             } else {
  //               this.closeConnection(
  //                 socket,
  //                 timeoutId,
  //                 false,
  //                 'Unexpected response',
  //                 resolve,
  //               );
  //             }
  //             break;
  //         }
  //       }
  //     });

  //     socket.on('error', (err) => {
  //       console.log('SMTP Error:', err.message);
  //       this.closeConnection(
  //         socket,
  //         timeoutId,
  //         false,
  //         `Connection error: ${err.message}`,
  //         resolve,
  //       );
  //     });
  //   });
  // }
  async verifyEmail(
    email: string,
    dnsResult: DnsVerificationResult,
    timeout = 10000,
  ): Promise<SmtpVerificationResult> {
    if (!dnsResult.hasMxRecord || dnsResult.mxRecords.length === 0) {
      return {
        success: false,
        exists: false,
        message: 'No MX records found for domain',
      };
    }

    const [username, domain] = email.split('@');

    return new Promise((resolve) => {
      // Using TLS socket instead of regular socket
      const socket = tls.connect({
        host: 'smtp.office365.com',  // Using Outlook's SMTP server
        port: 587,                   // Using submission port
        timeout: timeout
      });
      
      let buffer = '';
      let step = 0;

      const timeoutId = setTimeout(() => {
        socket.destroy();
        resolve({
          success: false,
          exists: false,
          message: 'Connection timeout',
        });
      }, timeout);

      // Monitor connection status
      socket.on('connect', () => {
        console.log('Connection established');
      });

      socket.on('timeout', () => {
        console.log('Connection timed out');
      });

      socket.on('data', (data) => {
        console.log('Raw server response:', data.toString());
        buffer += data.toString();

        if (buffer.includes('\r\n')) {
          const response = buffer.trim();
          buffer = '';

          switch (step) {
            case 0:
              console.log('Step 0 - Initial Connection Response:', response);
              if (response.startsWith('2')) {
                socket.write(`EHLO ${domain}\r\n`);  // Using EHLO instead of HELO for extended SMTP
                step++;
              } else {
                this.closeConnection(socket, timeoutId, false, 'Server not ready', resolve);
              }
              break;

            case 1:
              console.log('Step 1 - EHLO Response:', response);
              if (response.startsWith('2')) {
                // Start TLS negotiation
                socket.write('STARTTLS\r\n');
                step++;
              } else {
                this.closeConnection(socket, timeoutId, false, 'EHLO failed', resolve);
              }
              break;

            case 2:
              console.log('Step 2 - STARTTLS Response:', response);
              if (response.startsWith('2')) {
                socket.write(`MAIL FROM:<verify@${domain}>\r\n`);
                step++;
              } else {
                this.closeConnection(socket, timeoutId, false, 'STARTTLS failed', resolve);
              }
              break;

            case 3:
              console.log('Step 3 - MAIL FROM Response:', response);
              if (response.startsWith('2')) {
                socket.write(`RCPT TO:<${email}>\r\n`);
                step++;
              } else {
                this.closeConnection(socket, timeoutId, false, 'MAIL FROM failed', resolve);
              }
              break;

            case 4:
              console.log('Step 4 - RCPT TO Response:', response);
              if (response.startsWith('250')) {
                this.closeConnection(socket, timeoutId, true, 'Email exists', resolve);
              } else if (response.includes('blocked') || response.includes('Service unavailable')) {
                this.closeConnection(
                  socket,
                  timeoutId,
                  false,
                  'Verification failed: Server blocked our request',
                  resolve,
                );
              } else if (response.startsWith('550')) {
                this.closeConnection(socket, timeoutId, false, 'Email does not exist', resolve);
              } else {
                this.closeConnection(socket, timeoutId, false, 'Unexpected response', resolve);
              }
              break;
          }
        }
      });

      socket.on('error', (err) => {
        console.log('SMTP Error:', err.message);
        this.closeConnection(
          socket,
          timeoutId,
          false,
          `Connection error: ${err.message}`,
          resolve,
        );
      });
    });
  }
  private closeConnection(
    socket: any,
    timeoutId: NodeJS.Timeout,
    exists: boolean,
    message: string,
    resolve: (value: SmtpVerificationResult) => void,
  ): void {
    clearTimeout(timeoutId);
    socket.write('QUIT\r\n');
    socket.destroy();
    resolve({
      success: true,
      exists,
      message,
    });
  }

  // private closeConnection(
  //   socket: net.Socket,
  //   timeoutId: NodeJS.Timeout,
  //   exists: boolean,
  //   message: string,
  //   resolve: (value: SmtpVerificationResult) => void,
  // ): void {
  //   clearTimeout(timeoutId);
  //   socket.write('QUIT\r\n');
  //   socket.destroy();
  //   resolve({
  //     success: true,
  //     exists,
  //     message,
  //   });
  // }
}

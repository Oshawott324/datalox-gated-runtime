import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { CreateInventoryLevelInput, ExecArgs } from "@medusajs/framework/types";
import {
  ContainerRegistrationKeys,
  Modules,
  ProductStatus,
} from "@medusajs/framework/utils";
import {
  WorkflowResponse,
  createWorkflow,
  transform,
} from "@medusajs/framework/workflows-sdk";
import {
  createApiKeysWorkflow,
  createInventoryLevelsWorkflow,
  createProductCategoriesWorkflow,
  createProductsWorkflow,
  createRegionsWorkflow,
  createSalesChannelsWorkflow,
  createShippingOptionsWorkflow,
  createShippingProfilesWorkflow,
  createStockLocationsWorkflow,
  createTaxRegionsWorkflow,
  linkSalesChannelsToApiKeyWorkflow,
  linkSalesChannelsToStockLocationWorkflow,
  updateStoresStep,
  updateStoresWorkflow,
} from "@medusajs/medusa/core-flows";

const updateStoreCurrencies = createWorkflow(
  "datalox-update-store-currencies",
  (input: {
    supported_currencies: { currency_code: string; is_default?: boolean }[];
    store_id: string;
  }) => {
    const normalizedInput = transform({ input }, (data) => ({
      selector: { id: data.input.store_id },
      update: {
        supported_currencies: data.input.supported_currencies.map(
          (currency) => ({
            currency_code: currency.currency_code,
            is_default: currency.is_default ?? false,
          }),
        ),
      },
    }));

    return new WorkflowResponse(updateStoresStep(normalizedInput));
  },
);

export default async function seedDataloxMedusa({ container }: ExecArgs) {
  const logger = container.resolve(ContainerRegistrationKeys.LOGGER);
  const link = container.resolve(ContainerRegistrationKeys.LINK);
  const query = container.resolve(ContainerRegistrationKeys.QUERY);
  const fulfillmentModuleService = container.resolve(Modules.FULFILLMENT);
  const salesChannelModuleService = container.resolve(Modules.SALES_CHANNEL);
  const storeModuleService = container.resolve(Modules.STORE);

  const [store] = await storeModuleService.listStores();
  const countries = ["us"];

  logger.info("Seeding Datalox Medusa fixture sales channel.");
  let salesChannels = await salesChannelModuleService.listSalesChannels({
    name: "Datalox Probe Channel",
  });
  if (!salesChannels.length) {
    const { result } = await createSalesChannelsWorkflow(container).run({
      input: {
        salesChannelsData: [{ name: "Datalox Probe Channel" }],
      },
    });
    salesChannels = result;
  }
  const salesChannel = salesChannels[0];

  await updateStoreCurrencies(container).run({
    input: {
      store_id: store.id,
      supported_currencies: [{ currency_code: "usd", is_default: true }],
    },
  });
  await updateStoresWorkflow(container).run({
    input: {
      selector: { id: store.id },
      update: { default_sales_channel_id: salesChannel.id },
    },
  });

  logger.info("Seeding Datalox Medusa fixture region and tax region.");
  const { result: regionResult } = await createRegionsWorkflow(container).run({
    input: {
      regions: [
        {
          name: "Datalox United States",
          currency_code: "usd",
          countries,
          payment_providers: ["pp_system_default"],
        },
      ],
    },
  });
  const region = regionResult[0];
  await createTaxRegionsWorkflow(container).run({
    input: countries.map((country_code) => ({
      country_code,
      provider_id: "tp_system",
    })),
  });

  logger.info("Seeding Datalox Medusa fixture stock location and fulfillment.");
  const { result: stockLocationResult } = await createStockLocationsWorkflow(
    container,
  ).run({
    input: {
      locations: [
        {
          name: "Datalox Warehouse",
          address: {
            address_1: "1 Fixture Way",
            city: "New York",
            country_code: "US",
          },
        },
      ],
    },
  });
  const stockLocation = stockLocationResult[0];

  await updateStoresWorkflow(container).run({
    input: {
      selector: { id: store.id },
      update: { default_location_id: stockLocation.id },
    },
  });
  await link.create({
    [Modules.STOCK_LOCATION]: { stock_location_id: stockLocation.id },
    [Modules.FULFILLMENT]: { fulfillment_provider_id: "manual_manual" },
  });

  const shippingProfiles = await fulfillmentModuleService.listShippingProfiles({
    type: "default",
  });
  let shippingProfile = shippingProfiles[0];
  if (!shippingProfile) {
    const { result } = await createShippingProfilesWorkflow(container).run({
      input: { data: [{ name: "Datalox Default Shipping", type: "default" }] },
    });
    shippingProfile = result[0];
  }

  const fulfillmentSet = await fulfillmentModuleService.createFulfillmentSets({
    name: "Datalox Warehouse Shipping",
    type: "shipping",
    service_zones: [
      {
        name: "United States",
        geo_zones: [{ country_code: "us", type: "country" }],
      },
    ],
  });
  await link.create({
    [Modules.STOCK_LOCATION]: { stock_location_id: stockLocation.id },
    [Modules.FULFILLMENT]: { fulfillment_set_id: fulfillmentSet.id },
  });
  await createShippingOptionsWorkflow(container).run({
    input: [
      {
        name: "Datalox Standard",
        price_type: "flat",
        provider_id: "manual_manual",
        service_zone_id: fulfillmentSet.service_zones[0].id,
        shipping_profile_id: shippingProfile.id,
        type: {
          label: "Standard",
          description: "Fixture ground shipping.",
          code: "datalox-standard",
        },
        prices: [{ currency_code: "usd", amount: 10 }],
        rules: [
          { attribute: "enabled_in_store", operator: "eq", value: "true" },
          { attribute: "is_return", operator: "eq", value: "false" },
        ],
      },
    ],
  });
  await linkSalesChannelsToStockLocationWorkflow(container).run({
    input: { id: stockLocation.id, add: [salesChannel.id] },
  });

  logger.info("Seeding Datalox Medusa fixture publishable API key.");
  const {
    result: [publishableApiKey],
  } = await createApiKeysWorkflow(container).run({
    input: {
      api_keys: [
        {
          title: "Datalox Fixture Storefront",
          type: "publishable",
          created_by: "",
        },
      ],
    },
  });
  await linkSalesChannelsToApiKeyWorkflow(container).run({
    input: { id: publishableApiKey.id, add: [salesChannel.id] },
  });

  const productCount = 50;
  logger.info(`Seeding ${productCount} Datalox Medusa fixture products.`);
  const { result: categories } = await createProductCategoriesWorkflow(
    container,
  ).run({
    input: {
      product_categories: [{ name: "Datalox Fixtures", is_active: true }],
    },
  });
  const productInputs = Array.from({ length: productCount }, (_, index) => {
    const ordinal = String(index + 1).padStart(3, "0");
    return {
      title: `Datalox Pagination Item ${ordinal}`,
      handle: `datalox-pagination-item-${ordinal}`,
      description:
        "Self-authored synthetic product for bounded pagination probes.",
      status: ProductStatus.PUBLISHED,
      category_ids: [categories[0].id],
      shipping_profile_id: shippingProfile.id,
      options: [{ title: "Size", values: ["Standard"] }],
      variants: [
        {
          title: "Standard",
          sku: `DATALOX-PAGINATION-${ordinal}`,
          manage_inventory: true,
          options: { Size: "Standard" },
          prices: [{ amount: 1000 + index, currency_code: "usd" }],
        },
      ],
      sales_channels: [{ id: salesChannel.id }],
    };
  });
  const { result: products } = await createProductsWorkflow(container).run({
    input: { products: productInputs },
  });

  const { data: inventoryItems } = await query.graph({
    entity: "inventory_item",
    fields: ["id"],
  });
  const inventoryLevels: CreateInventoryLevelInput[] = inventoryItems.map(
    (inventoryItem) => ({
      location_id: stockLocation.id,
      stocked_quantity: 100,
      inventory_item_id: inventoryItem.id,
    }),
  );
  await createInventoryLevelsWorkflow(container).run({
    input: { inventory_levels: inventoryLevels },
  });

  const { data: apiKeys } = await query.graph({
    entity: "api_key",
    fields: ["id", "token", "title", "type"],
    filters: { id: publishableApiKey.id },
  });
  const { data: variants } = await query.graph({
    entity: "product_variant",
    fields: ["id", "sku"],
    filters: { sku: "DATALOX-PAGINATION-001" },
  });

  const fixture = {
    api_key_id: publishableApiKey.id,
    product_count: productCount,
    product_id: products[0].id,
    product_ids: products.map((product) => product.id),
    publishable_api_key: apiKeys[0]?.token,
    region_id: region.id,
    sales_channel_id: salesChannel.id,
    stock_location_id: stockLocation.id,
    variant_id: variants[0]?.id,
  };
  writeFileSync(
    resolve(process.cwd(), ".datalox-medusa-fixture.json"),
    `${JSON.stringify(fixture, null, 2)}\n`,
  );
  logger.info("Finished seeding Datalox Medusa fixture.");
}
